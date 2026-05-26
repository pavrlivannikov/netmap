<script>
  export let deviceCount = 0;
  export let scanning = false;
</script>

<footer class="statusbar">
  <div class="status-left">
    {#if scanning}
      <span class="scan-indicator">⚡ Сканирование…</span>
    {:else}
      <span>Устройств в сети: <strong>{deviceCount}</strong></span>
    {/if}
  </div>
  <div class="status-right">
    <span class="hint">Кликните на устройство для деталей</span>
  </div>
</footer>

<style>
  .statusbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 6px 16px;
    background: #1e293b;
    border-top: 1px solid #334155;
    font-size: 12px;
    color: #64748b;
  }

  .scan-indicator {
    color: #38bdf8;
    animation: pulse 1.5s ease-in-out infinite;
  }

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }

  .hint {
    font-style: italic;
  }
</style>
