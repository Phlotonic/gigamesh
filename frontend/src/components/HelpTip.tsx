import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { GLOSSARY, type GlossaryKey } from '../glossary';

interface HelpTipProps {
  /** Key from the shared plain-English glossary. */
  term?: GlossaryKey;
  /** Optional custom heading (overrides glossary title). */
  title?: string;
  /** Optional custom plain-English explanation (overrides glossary body). */
  body?: string;
  /** Optional "Why it matters" note. */
  why?: string;
  /** Optional custom trigger element instead of the default "?" badge. */
  children?: React.ReactNode;
}

const TOOLTIP_WIDTH = 280;
const EDGE_MARGIN = 12;
const GAP = 8;

export function HelpTip({ term, title, body, why, children }: HelpTipProps) {
  const entry = term ? GLOSSARY[term] : undefined;
  const resolvedTitle = title ?? entry?.title ?? '';
  const resolvedBody = body ?? entry?.body ?? '';
  const resolvedWhy = why ?? (entry && 'why' in entry ? entry.why : undefined);

  const [hovered, setHovered] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number; placement: 'top' | 'bottom' }>({
    top: 0,
    left: 0,
    placement: 'bottom',
  });

  const open = hovered || pinned;
  const triggerRef = useRef<HTMLSpanElement | null>(null);
  const tipRef = useRef<HTMLDivElement | null>(null);
  const tipId = useId();

  const updatePosition = useCallback(() => {
    const el = triggerRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const tipHeight = tipRef.current?.offsetHeight ?? 110;
    const tipWidth = tipRef.current?.offsetWidth ?? TOOLTIP_WIDTH;

    const spaceBelow = window.innerHeight - rect.bottom;
    const placement: 'top' | 'bottom' =
      spaceBelow >= tipHeight + GAP + EDGE_MARGIN || spaceBelow >= rect.top ? 'bottom' : 'top';

    const top =
      placement === 'bottom'
        ? Math.min(rect.bottom + GAP, window.innerHeight - tipHeight - EDGE_MARGIN)
        : Math.max(EDGE_MARGIN, rect.top - tipHeight - GAP);

    const centeredLeft = rect.left + rect.width / 2 - tipWidth / 2;
    const left = Math.max(EDGE_MARGIN, Math.min(centeredLeft, window.innerWidth - tipWidth - EDGE_MARGIN));

    setPos({ top, left, placement });
  }, []);

  useLayoutEffect(() => {
    if (!open) return;
    updatePosition();
  }, [open, updatePosition]);

  useEffect(() => {
    if (!open) return;
    const onWindowChange = () => updatePosition();
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setPinned(false);
        setHovered(false);
      }
    };
    const onDocPointerDown = (e: MouseEvent) => {
      const target = e.target as Node | null;
      if (
        target &&
        !triggerRef.current?.contains(target) &&
        !tipRef.current?.contains(target)
      ) {
        setPinned(false);
        setHovered(false);
      }
    };

    window.addEventListener('resize', onWindowChange);
    window.addEventListener('scroll', onWindowChange, true);
    document.addEventListener('keydown', onKeyDown);
    document.addEventListener('mousedown', onDocPointerDown);
    return () => {
      window.removeEventListener('resize', onWindowChange);
      window.removeEventListener('scroll', onWindowChange, true);
      document.removeEventListener('keydown', onKeyDown);
      document.removeEventListener('mousedown', onDocPointerDown);
    };
  }, [open, updatePosition]);

  if (!resolvedBody) return <>{children}</>;

  const portal = open
    ? createPortal(
        <div
          ref={tipRef}
          id={tipId}
          role="tooltip"
          className={`gm-tooltip gm-tooltip-${pos.placement}`}
          style={{ top: pos.top, left: pos.left }}
          onMouseEnter={() => setHovered(true)}
          onMouseLeave={() => setHovered(false)}
        >
          {resolvedTitle && <div className="gm-tooltip-title">{resolvedTitle}</div>}
          <div className="gm-tooltip-body">{resolvedBody}</div>
          {resolvedWhy && (
            <div className="gm-tooltip-why">
              <strong>Why it matters:</strong> {resolvedWhy}
            </div>
          )}
        </div>,
        document.body
      )
    : null;

  if (children) {
    return (
      <span
        ref={triggerRef}
        className="gm-tip-wrap"
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        onFocus={() => setHovered(true)}
        onBlur={() => setHovered(false)}
        aria-describedby={open ? tipId : undefined}
      >
        {children}
        {portal}
      </span>
    );
  }

  return (
    <span ref={triggerRef} className="gm-tip-anchor">
      <button
        type="button"
        className={`gm-help-icon ${pinned ? 'pinned' : ''}`}
        aria-label={`Explain: ${resolvedTitle || 'this item'}`}
        aria-expanded={open}
        aria-describedby={open ? tipId : undefined}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        onFocus={() => setHovered(true)}
        onBlur={() => setHovered(false)}
        onClick={(e) => {
          e.stopPropagation();
          setPinned((p) => !p);
        }}
      >
        ?
      </button>
      {portal}
    </span>
  );
}
