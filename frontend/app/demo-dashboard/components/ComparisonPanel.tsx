"use client";

export interface ComparisonRow {
  label: string;
  without: string;
  withTesht: string;
}

interface ComparisonPanelProps {
  rows?: ComparisonRow[];
}

export function ComparisonPanel({ rows }: ComparisonPanelProps) {
  if (!rows || rows.length === 0) return null;

  return (
    <div className="mt-5">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">
        How does this compare?
      </p>
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {/* Column headers */}
        <div className="grid grid-cols-3 border-b border-gray-200">
          <div className="px-4 py-3 bg-gray-50">
            <span className="text-xs font-semibold text-gray-500">Capability</span>
          </div>
          <div className="px-4 py-3 bg-red-50 border-l border-gray-200">
            <span className="text-xs font-semibold text-red-600">Without Tesht</span>
          </div>
          <div className="px-4 py-3 bg-emerald-50 border-l border-gray-200">
            <span className="text-xs font-semibold text-emerald-700">With Tesht</span>
          </div>
        </div>

        {/* Data rows */}
        {rows.map((row, i) => (
          <div
            key={i}
            className="grid grid-cols-3 border-b border-gray-100 last:border-b-0 hover:bg-gray-50/50 transition-colors"
          >
            <div className="px-4 py-3">
              <span className="text-xs font-medium text-gray-700">{row.label}</span>
            </div>
            <div className="px-4 py-3 border-l border-gray-100">
              <div className="flex items-start gap-1.5">
                <span className="flex-shrink-0 text-red-400 text-xs mt-0.5">✗</span>
                <span className="text-xs text-gray-500 leading-relaxed">{row.without}</span>
              </div>
            </div>
            <div className="px-4 py-3 border-l border-gray-100 bg-emerald-50/30">
              <div className="flex items-start gap-1.5">
                <span className="flex-shrink-0 text-emerald-500 text-xs mt-0.5">✓</span>
                <span className="text-xs text-emerald-800 font-medium leading-relaxed">{row.withTesht}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
