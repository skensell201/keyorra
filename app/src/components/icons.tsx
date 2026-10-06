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
export const IconPencil = icon(<path d="M5 19l1-4.5L15.5 5a2.1 2.1 0 013 3L9 17.5zM13.5 7l3 3" />);
export const IconShield = icon(<path d="M12 3.5l7 2.8v5.2c0 4.3-2.9 7.6-7 9-4.1-1.4-7-4.7-7-9V6.3z" />);
export const IconClose = icon(<path d="M6 6l12 12M18 6L6 18" />);
export const IconSliders = icon(
  <>
    <path d="M4 7h9M17 7h3M4 17h3M11 17h9" />
    <circle cx="15" cy="7" r="2" />
    <circle cx="9" cy="17" r="2" />
  </>,
);
export const IconSync = icon(
  <>
    <path d="M19.5 9.5A7.5 7.5 0 006.2 6.8L4.5 8.5M4.5 4.5v4h4" />
    <path d="M4.5 14.5a7.5 7.5 0 0013.3 2.7l1.7-1.7M19.5 19.5v-4h-4" />
  </>,
);
export const IconGlobe = icon(
  <>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M3.5 12h17M12 3.5c2.3 2.4 3.4 5.2 3.4 8.5s-1.1 6.1-3.4 8.5c-2.3-2.4-3.4-5.2-3.4-8.5S9.7 5.9 12 3.5z" />
  </>,
);
export const IconLaptop = icon(
  <>
    <rect x="5" y="5" width="14" height="10" rx="1.8" />
    <path d="M2.5 18.5h19" />
  </>,
);
export const IconAlert = icon(
  <>
    <path d="M12 4l9 15.5H3z" />
    <path d="M12 10v4.5M12 17h.01" />
  </>,
);
export const IconShieldCheck = icon(
  <>
    <path d="M12 3.5l7 2.8v5.2c0 4.3-2.9 7.6-7 9-4.1-1.4-7-4.7-7-9V6.3z" />
    <path d="M9 12l2.2 2.2L15.5 10" />
  </>,
);
export const IconLifebuoy = icon(
  <>
    <circle cx="12" cy="12" r="8.5" />
    <circle cx="12" cy="12" r="3.5" />
    <path d="M6 6l3.5 3.5M14.5 14.5L18 18M18 6l-3.5 3.5M9.5 14.5L6 18" />
  </>,
);
export const IconFolder = icon(<path d="M3.5 7.5a2 2 0 012-2h4l2 2h7a2 2 0 012 2v8a2 2 0 01-2 2h-13a2 2 0 01-2-2z" />);
export const IconArchive = icon(
  <>
    <rect x="3.5" y="4.5" width="17" height="4" rx="1.2" />
    <path d="M5 8.5v9.5a1.5 1.5 0 001.5 1.5h11a1.5 1.5 0 001.5-1.5V8.5M10 12.5h4" />
  </>,
);

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
