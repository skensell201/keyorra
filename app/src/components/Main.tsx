export function Main({ onLock }: { onLock: () => void }) {
  return (
    <div className="center">
      <button onClick={onLock}>Lock</button>
    </div>
  );
}
