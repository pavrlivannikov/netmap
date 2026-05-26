<script>
  export let scanSubnet = "192.168.1.0/24";
  export let scanning = false;
  export let layoutMode = "cose";
  export let onScan;
  export let onToggleLayout;
  export let onExport;
  export let onChangeNetwork = null;
</script>

<header class="toolbar">
  <div class="brand">
    <span class="logo">🦊</span>
    <span class="title">NetMap</span>
    <span class="version">v0.1</span>
  </div>

  <div class="controls">
    <div class="input-group">
      <input
        type="text"
        bind:value={scanSubnet}
        placeholder="192.168.1.0/24"
        disabled={scanning}
        class="subnet-input"
      />
      <button on:click={onScan} disabled={scanning} class="btn btn-primary">
        {#if scanning}
          <span class="spinner" /> Сканирую…
        {:else}
          🔍 Сканировать
        {/if}
      </button>
    </div>

    <div class="actions">
      {#if onChangeNetwork}
        <button on:click={onChangeNetwork} class="btn btn-ghost" title="Сменить сеть">
          🌐 Сеть
        </button>
      {/if}
      <button on:click={onToggleLayout} class="btn btn-ghost" title="Сменить раскладку">
        {layoutMode === "cose" ? "⬡ Силовая" : "⬍ Иерархия"}
      </button>
      <button on:click={() => onExport("png")} class="btn btn-ghost" title="Экспорт PNG">
        📥 PNG
      </button>
      <button on:click={() => onExport("svg")} class="btn btn-ghost" title="Экспорт SVG">
        📥 SVG
      </button>
    </div>
  </div>
</header>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: #1e293b;
    border-bottom: 1px solid #334155;
    gap: 16px;
    flex-wrap: wrap;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .logo {
    font-size: 24px;
  }

  .title {
    font-weight: 700;
    font-size: 18px;
    color: #f1f5f9;
  }

  .version {
    font-size: 11px;
    color: #64748b;
    background: #334155;
    padding: 2px 6px;
    border-radius: 4px;
  }

  .controls {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }

  .input-group {
    display: flex;
    gap: 6px;
  }

  .subnet-input {
    background: #0f172a;
    border: 1px solid #475569;
    color: #e2e8f0;
    padding: 8px 12px;
    border-radius: 6px;
    font-family: "Inter", monospace;
    font-size: 14px;
    width: 180px;
    outline: none;
  }

  .subnet-input:focus {
    border-color: #38bdf8;
  }

  .btn {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 14px;
    border: none;
    border-radius: 6px;
    font-family: "Inter", sans-serif;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-primary {
    background: #2563eb;
    color: white;
  }

  .btn-primary:hover:not(:disabled) {
    background: #1d4ed8;
  }

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .btn-ghost {
    background: transparent;
    color: #94a3b8;
    border: 1px solid #334155;
  }

  .btn-ghost:hover {
    background: #334155;
    color: #e2e8f0;
  }

  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid #ffffff44;
    border-top-color: white;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
