export const deviceStyles = [
  {
    selector: "node",
    style: {
      "background-color": "#334155",
      "background-image": (el) => `url(/icons/${el.data("type") || "unknown"}.svg)`,
      "background-fit": "contain",
      "background-width": "60%",
      "background-height": "60%",
      label: "data(label)",
      "font-family": "Inter, sans-serif",
      "font-size": "11px",
      color: "#94a3b8",
      "text-valign": "bottom",
      "text-margin-y": 6,
      width: 64,
      height: 64,
      "border-width": 3,
      "border-color": "#475569",
      "transition-duration": "0.3s",
      "transition-property": "border-color, background-color",
    },
  },
  {
    selector: "node[status='online']",
    style: {
      "border-color": "#22c55e",
      "background-color": "#1a3a2a",
    },
  },
  {
    selector: "node[status='offline']",
    style: {
      "border-color": "#ef4444",
      "background-color": "#3a1a1a",
      opacity: 0.5,
    },
  },
  {
    selector: "node[status='unknown']",
    style: {
      "border-color": "#eab308",
      "background-color": "#3a351a",
    },
  },
  {
    selector: "node:selected",
    style: {
      "border-color": "#38bdf8",
      "border-width": 4,
      "background-color": "#1a2e3a",
    },
  },
];

export const edgeStyles = [
  {
    selector: "edge",
    style: {
      width: 2,
      "line-color": "#475569",
      "target-arrow-color": "#475569",
      "target-arrow-shape": "triangle",
      "curve-style": "bezier",
      "transition-duration": "0.3s",
    },
  },
  {
    selector: "edge[type='wireless']",
    style: {
      "line-style": "dashed",
      "line-color": "#6366f1",
    },
  },
];
