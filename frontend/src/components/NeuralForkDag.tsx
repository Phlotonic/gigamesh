import { useMemo } from 'react';
import type { ForkGenome } from '../types';

interface Props {
  forks: ForkGenome[];
  selectedForkId: string | null;
  onSelectFork: (fork: ForkGenome) => void;
}

export function NeuralForkDag({ forks, selectedForkId, onSelectFork }: Props) {
  const layout = useMemo(() => {
    const byGen = new Map<number, ForkGenome[]>();
    for (const f of forks) {
      const list = byGen.get(f.generation) || [];
      list.push(f);
      byGen.set(f.generation, list);
    }
    const gens = Array.from(byGen.keys()).sort((a, b) => a - b);
    const positions = new Map<string, { x: number; y: number }>();
    const colWidth = 225;
    const rowHeight = 76;
    let maxY = 260;

    gens.forEach((g, colIdx) => {
      const list = byGen.get(g) || [];
      list.forEach((fork, rowIdx) => {
        const x = 28 + colIdx * colWidth;
        const y = 30 + rowIdx * rowHeight;
        positions.set(fork.fork_id, { x, y });
        if (y + 84 > maxY) maxY = y + 84;
      });
    });

    const width = Math.max(720, 60 + gens.length * colWidth);
    return { positions, width, height: maxY };
  }, [forks]);

  return (
    <div className="gm-svg-frame">
      <svg width={layout.width} height={layout.height} role="img" aria-label="GigaMesh Immutable Git Neural Fork DAG">
        {/* Edges */}
        {forks.map((fork) => {
          if (!fork.parent_fork_id) return null;
          const p = layout.positions.get(fork.parent_fork_id);
          const c = layout.positions.get(fork.fork_id);
          if (!p || !c) return null;
          const isCulled = fork.status === 'culled';
          const x1 = p.x + 186;
          const y1 = p.y + 26;
          const x2 = c.x;
          const y2 = c.y + 26;
          const mid = (x1 + x2) / 2;
          return (
            <path
              key={`${fork.parent_fork_id}->${fork.fork_id}`}
              d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
              fill="none"
              stroke={isCulled ? '#cfa09c' : fork.status === 'champion' ? '#16684a' : '#7b8794'}
              strokeWidth={fork.status === 'champion' ? 2.2 : 1.4}
              strokeDasharray={isCulled ? '4 4' : undefined}
            />
          );
        })}

        {/* Nodes */}
        {forks.map((fork) => {
          const pos = layout.positions.get(fork.fork_id);
          if (!pos) return null;
          const selected = fork.fork_id === selectedForkId;
          const isChampion = fork.status === 'champion';
          const isCulled = fork.status === 'culled';
          const sr = fork.benchmark_stats ? (fork.benchmark_stats.composite_success_rate * 100).toFixed(1) : '—';

          const fill = isChampion ? '#e7f4ee' : isCulled ? '#fbeceb' : '#ffffff';
          const stroke = selected ? '#141619' : isChampion ? '#16684a' : isCulled ? '#b32d24' : '#c4bdb0';

          return (
            <g
              key={fork.fork_id}
              transform={`translate(${pos.x}, ${pos.y})`}
              style={{ cursor: 'pointer' }}
              onClick={() => onSelectFork(fork)}
            >
              <rect
                width={186}
                height={54}
                rx={6}
                fill={fill}
                stroke={stroke}
                strokeWidth={selected ? 2.2 : 1.2}
                strokeDasharray={isCulled ? '4 3' : undefined}
              />
              <text
                x={10}
                y={19}
                fontSize={11}
                fontWeight={600}
                fontFamily="JetBrains Mono, monospace"
                fill="#141619"
              >
                {fork.fork_id.length > 21 ? `${fork.fork_id.slice(0, 20)}…` : fork.fork_id}
              </text>
              <text
                x={10}
                y={35}
                fontSize={10.5}
                fontFamily="Inter, sans-serif"
                fill="#4e545e"
              >
                {fork.use_case}
              </text>
              <text
                x={176}
                y={46}
                textAnchor="end"
                fontSize={10.5}
                fontWeight={600}
                fontFamily="JetBrains Mono, monospace"
                fill={isChampion ? '#16684a' : isCulled ? '#b32d24' : '#1d4c8a'}
              >
                {isCulled ? 'CULLED' : `${sr}% SR`}
              </text>
              <text
                x={10}
                y={47}
                fontSize={9.5}
                fontFamily="JetBrains Mono, monospace"
                fill="#767d89"
              >
                g{fork.generation} · {fork.git_commit_sha ? fork.git_commit_sha.slice(0, 7) : 'pending'}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
