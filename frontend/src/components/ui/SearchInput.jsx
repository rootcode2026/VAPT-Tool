import { IconSearch } from "@/components/icons";

export default function SearchInput({
  value,
  onChange,
  placeholder = "Search",
  id = "search",
  label = "Search",
}) {
  return (
    <div className="relative min-w-0 flex-1">
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <IconSearch className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
      <input
        id={id}
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="w-full rounded-sm border border-border bg-canvas py-2 pl-9 pr-3 text-sm text-text placeholder:text-muted"
      />
    </div>
  );
}
