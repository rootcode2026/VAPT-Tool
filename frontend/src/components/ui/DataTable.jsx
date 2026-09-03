export default function DataTable({ columns, rows, empty, rowKey }) {
  if (!rows?.length) {
    return empty || null;
  }

  return (
    <>
      <ul className="space-y-3 md:hidden">
        {rows.map((row, index) => (
          <li
            key={rowKey ? rowKey(row) : index}
            className="rounded-md border border-border bg-surface p-3"
          >
            {columns.map((column) => (
              <div
                key={column.key}
                className="flex items-start justify-between gap-3 border-b border-border py-2 last:border-0 last:pb-0 first:pt-0"
              >
                <span className="shrink-0 text-xs text-muted">{column.header}</span>
                <span className="min-w-0 break-words text-right text-sm text-text">
                  {column.render ? column.render(row) : row[column.key]}
                </span>
              </div>
            ))}
          </li>
        ))}
      </ul>
      <div className="hidden overflow-x-auto rounded-md border border-border md:block">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b border-border bg-surface-hover text-xs uppercase tracking-wide text-muted">
            <tr>
              {columns.map((column) => (
                <th key={column.key} className="whitespace-nowrap px-3 py-2.5 font-medium">
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr
                key={rowKey ? rowKey(row) : index}
                className="border-b border-border last:border-0 hover:bg-surface-hover/60"
              >
                {columns.map((column) => (
                  <td key={column.key} className="max-w-[18rem] truncate px-3 py-2.5 text-text">
                    {column.render ? column.render(row) : row[column.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
