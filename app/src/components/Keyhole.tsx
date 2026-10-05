import type { SVGProps } from "react";

/** The Keepsake mark: a keyhole. Inherits the text colour. */
export function Keyhole(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" {...props}>
      <circle cx="12" cy="9" r="4" fill="currentColor" />
      <path d="M10.2 11.5h3.6l1.2 8h-6z" fill="currentColor" />
    </svg>
  );
}
