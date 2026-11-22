import { useMemo } from 'react';
import type { ProvenanceSnapshot } from '../types';

interface Props {
  snapshot: ProvenanceSnapshot;
}

const LAYER_ORDER: Record<string, number> = {
  human: 0,
  external_source: 0,
  agent: 1,
  red_hat_suspect: 1,
  sub_agent: 2,
  mcp_tool: 3,
  rhel_host: 4,
  host: 4,
  egress: 5,
};

export function ProvenanceGraph({ snapshot }: Props) {
  const layout = useMemo(() => {
    const layers = new Map<number, ProvenanceSnapshot['nodes']>();
    for (const node of snapshot.nodes) {
      const col = LAYER_ORDER[node.kind || 'agent'] ?? 2;
      const list = layers.get(col) || [];
      list.push(node);
      layers.set(col, list);
    }

    const pos = new Map<string, { x: number; y: number }>();
    const colW = 195;
    const rowH = 66;
    let maxH = 220;
    const cols = Array.from(layers.keys()).sort((a, b) => a - b);

    cols.forEach((col, cIdx) => {
      const list = layers.get(col) || [];
      list.forEach((n, rIdx) => {
        const x = 22 + cIdx * colW;
        const y = 24 + rIdx * rowH;
        pos.set(n.id, { x, y });
        if (y + 72 > maxH) maxH = y + 72;
      });
    });

    return { pos, width: Math.max(760, 40 + cols.length * colW), height: maxH };
  }, [snapshot]);

  if (snapshot.nodes.length === 0) {
    return (
      <div className="gm-item-box">
        <p className="gm-muted" style={{ margin: 0 }}>
          No causal nodes ingested yet. Launch one of the multi-hop attack scenarios above to trace Human → Delegation → Agent → Tool/MCP → RHEL Host provenance in real time.
        </p>
      </div>
    );
  }

  return (
    <div className="gm-svg-frame">
      <svg width={layout.width} height={layout.height} role="img" aria-label="Causal Provenance Graph">
        {snapshot.edges.map((e, idx) => {
          const s = layout.pos.get(e.source);
          const t = layout.pos.get(e.target);
          if (!s || !t) return null;
          const x1 = s.x + 162;
          const y1 = s.y + 22;
          const x2 = t.x;
          const y2 = t.y + 22;
          const mid = (x1 + x2) / 2;
          const hot = e.tainted || e.privilege_amplified;
          return (
            <g key={`${e.source}-${e.target}-${idx}`}>
              <path
                d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                fill="none"
                stroke={hot ? '#b32d24' : '#7b8794'}
                strokeWidth={hot ? 2 : 1.3}
              />
              <text
                x={mid}
                y={(y1 + y2) / 2 - 4}
                textAnchor="middle"
                fontSize={9}
                fontFamily="JetBrains Mono, monospace"
                fill={hot ? '#b32d24' : '#767d89'}
              >
                {e.relation}
              </text>
            </g>
          );
        })}

        {snapshot.nodes.map((node) => {
          const p = layout.pos.get(node.id);
          if (!p) return null;
          const tainted = Boolean(node.tainted);
          const isHost = node.kind === 'rhel_host' || node.kind === 'red_hat_suspect';
          const fill = tainted ? '#fbeceb' : isHost ? '#fbf3e6' : '#ffffff';
          const stroke = tainted ? '#b32d24' : isHost ? '#9c5b11' : '#1d4c8a';
          const label = node.label || node.id;

          return (
            <g key={node.id} transform={`translate(${p.x}, ${p.y})`}>
              <rect width={162} height={44} rx={6} fill={fill} stroke={stroke} strokeWidth={1.3} />
              <text x={8} y={17} fontSize={9.5} fontWeight={600} fontFamily="JetBrains Mono, monospace" fill={stroke}>
                {(node.kind || 'node').toUpperCase()}
              </text>
              <text x={8} y={33} fontSize={11} fontFamily="Inter, sans-serif" fill="#141619">
                {label.length > 20 ? `${label.slice(0, 19)}…` : label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
