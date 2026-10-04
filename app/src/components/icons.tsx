import type { ReactNode, SVGProps } from "react";
import type { ItemKind } from "../api";

/** One stroke icon set (24px grid, 1.75 stroke), coloured by `currentColor`. Decorative: aria-hidden. */
function icon(paths: ReactNode) {
  return function Icon(props: SVGProps<SVGSVGElement>) {
    return (
      <svg
        viewBox="0 0 24 24"
        width="16"
        height="16"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        {...props}
      >
        {paths}
      </svg>
    );
  };
}

export const IconGrid = icon(
  <>
    <rect x="3.5" y="3.5" width="7" height="7" rx="2" />
    <rect x="13.5" y="3.5" width="7" height="7" rx="2" />
    <rect x="3.5" y="13.5" width="7" height="7" rx="2" />
    <rect x="13.5" y="13.5" width="7" height="7" rx="2" />
  </>,
);
export const IconStar = icon(<path d="M12 3.8l2.5 5.1 5.6.8-4 3.9.9 5.6-5-2.6-5 2.6.9-5.6-4-3.9 5.6-.8z" />);
export const IconTrash = icon(
  <>
    <path d="M4 7h16M9.5 7V4.5h5V7M6 7l1 12.5h10L18 7" />
    <path d="M10 11v5M14 11v5" />
  </>,
);
export const IconVault = icon(
  <>
    <rect x="3.5" y="4.5" width="17" height="15" rx="3" />
    <circle cx="12" cy="12" r="3.2" />
    <path d="M12 8.8v-1M12 16.2v-1M15.2 12h1M7.8 12h1" />
  </>,
);
export const IconPlus = icon(<path d="M12 5v14M5 12h14" />);
export const IconImport = icon(
  <>
    <path d="M12 4v11M7.5 10.5L12 15l4.5-4.5" />
    <path d="M5 19.5h14" />
  </>,
);
export const IconSettings = icon(
  <>
    <circle cx="12" cy="12" r="3" />
    <path d="M12 3.5v2.2M12 18.3v2.2M20.5 12h-2.2M5.7 12H3.5M18 6l-1.6 1.6M7.6 16.4L6 18M18 18l-1.6-1.6M7.6 7.6L6 6" />
  </>,
);
export const IconLock = icon(
  <>
    <rect x="5" y="10.5" width="14" height="10" rx="2.5" />
    <path d="M8.5 10.5V8a3.5 3.5 0 017 0v2.5" />
  </>,
);
export const IconSearch = icon(
  <>
    <circle cx="11" cy="11" r="6.5" />
    <path d="M20 20l-4.2-4.2" />
  </>,
);
export const IconCopy = icon(
  <>
    <rect x="8.5" y="8.5" width="11" height="11" rx="2.5" />
    <path d="M15.5 8.5V6a2 2 0 00-2-2h-7a2 2 0 00-2 2v7a2 2 0 002 2h2" />
  </>,
);
export const IconCheck = icon(<path d="M5 12.5l4.5 4.5L19 7.5" />);
export const IconEye = icon(
  <>
    <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />
    <circle cx="12" cy="12" r="3" />
  </>,
);
export const IconEyeOff = icon(
  <>
    <path d="M4 4l16 16" />
    <path d="M9.9 5.8A9.7 9.7 0 0112 5.5c6 0 9.5 6.5 9.5 6.5a16 16 0 01-2.7 3.4M6.4 7.4C3.9 9.1 2.5 12 2.5 12S6 18.5 12 18.5a9.4 9.4 0 004.2-1" />
  </>,
);
export const IconClose = icon(<path d="M6 6l12 12M18 6L6 18" />);

const KIND_ICON: Record<ItemKind, ReturnType<typeof icon>> = {
  login: icon(
    <>
      <circle cx="8.5" cy="12" r="4" />
      <path d="M12.5 12H21M18 12v3M21 12v2" />
    </>,
  ),
  secure_note: icon(
    <>
      <path d="M6 3.5h9l3.5 3.5v13.5H6z" />
      <path d="M9 11h6M9 15h6" />
    </>,
  ),
  password: icon(
    <>
      <rect x="3.5" y="7.5" width="17" height="9" rx="3" />
      <path d="M8 12h.01M12 12h.01M16 12h.01" />
    </>,
  ),
  credit_card: icon(
    <>
      <rect x="3" y="5.5" width="18" height="13" rx="2.5" />
      <path d="M3 10h18M7 15h3" />
    </>,
  ),
  identity: icon(
    <>
      <circle cx="12" cy="9" r="3.5" />
      <path d="M5.5 19.5a6.5 6.5 0 0113 0" />
    </>,
  ),
  api_credential: icon(<path d="M8.5 7L3.5 12l5 5M15.5 7l5 5-5 5M13.5 5l-3 14" />),
};

export function KindIcon({ kind, ...props }: { kind: ItemKind } & SVGProps<SVGSVGElement>) {
  const Icon = KIND_ICON[kind];
  return <Icon {...props} />;
}
