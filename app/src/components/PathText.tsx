import { useEffect, useRef, useState } from "react";
import { IconCheck, IconCopy } from "./icons";

/** Splits a path so that its last two parts stay visible when the start is cut. */
export function splitPath(path: string): [string, string] {
  const parts = path.split("/");
  if (parts.length <= 3) return ["", path];
  const tail = parts.slice(-2).join("/");
  return [path.slice(0, path.length - tail.length), tail];
}

/**
 * A long path on one line, shortened in the middle: the start gives way, the folder names at
 * the end stay. The whole path is in the tooltip, read out in full and copied with the button.
 */
export function PathText({ path, label = "path" }: { path: string; label?: string }) {
  const [head, tail] = splitPath(path);
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  async function copy() {
    try {
      await navigator.clipboard.writeText(path);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }
  return (
    <span className="path-line">
      <span className="path mono" title={path}>
        {/* Drawn from attributes, so the page holds the path as text once: in full. */}
        <span className="path-head" aria-hidden="true" data-text={head} />
        <span className="path-tail" aria-hidden="true" data-text={tail} />
        <span className="sr-only">{path}</span>
      </span>
      <button
        type="button"
        className={copied ? "icon done" : "icon"}
        aria-label={copied ? "Copied" : `Copy ${label}`}
        title={`Copy ${label}`}
        onClick={copy}
      >
        {copied ? <IconCheck /> : <IconCopy />}
      </button>
    </span>
  );
}
