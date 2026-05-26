<script>
  import { createEventDispatcher } from "svelte";

  export let networks = [];
  export let scanning = false;

  let dispatch = createEventDispatcher();
  let showManual = false;
  let manualSubnet = "192.168.1.0/24";

  function selectNetwork(network) {
    dispatch("select", { subnet: network.cidr });
  }

  function selectManual() {
    if (manualSubnet && manualSubnet.includes("/")) {
      dispatch("select", { subnet: manualSubnet });
    }
  }
</script>

<div class="selector-overlay">
  <div class="selector-card">
    <h2>🌐 Выберите сеть для сканирования</h2>

    {#if scanning}
      <div class="scanning-msg">🔍 Сканирование...</div>
    {:else if networks.length > 0}
      <p class="hint">Найдено сетей: {networks.length}</p>
      <div class="network-list">
        {#each networks as net}
          <button class="net-card" on:click={() => selectNetwork(net)}>
            <span class="net-iface">{net.interface}</span>
            <span class="net-desc">{net.description}</span>
            <span class="net-ip">{net.ip}/{net.prefix}</span>
            {#if net.gateway}
              <span class="net-gw">шлюз: {net.gateway}</span>
            {/if}
          </button>
        {/each}
      </div>
    {:else}
      <p class="hint">Сети не найдены — введите вручную</p>
    {/if}

    <div class="manual-section">
      <button class="toggle-manual" on:click={() => (showManual = !showManual)}>
        {showManual ? "▲ Скрыть" : "▼ Ручной ввод"}
      </button>

      {#if showManual}
        <div class="manual-input">
          <input
            type="text"
            bind:value={manualSubnet}
            placeholder="192.168.1.0/24"
          />
          <button class="btn-scan" on:click={selectManual}>🔍 Сканировать</button>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .selector-overlay {
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.92);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .selector-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 16px;
    padding: 32px;
    max-width: 520px;
    width: 90%;
    max-height: 80vh;
    overflow-y: auto;
  }

  h2 {
    margin: 0 0 16px;
    font-size: 1.3rem;
    color: #e2e8f0;
  }

  .hint {
    color: #94a3b8;
    font-size: 0.9rem;
    margin: 0 0 16px;
  }

  .scanning-msg {
    text-align: center;
    padding: 32px;
    font-size: 1.1rem;
    color: #60a5fa;
  }

  .network-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 16px;
  }

  .net-card {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 4px 16px;
    padding: 14px 18px;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 10px;
    cursor: pointer;
    text-align: left;
    color: #e2e8f0;
    transition: all 0.15s;
  }

  .net-card:hover {
    border-color: #60a5fa;
    background: #1e3a5f;
  }

  .net-iface {
    font-weight: 700;
    font-size: 1rem;
    color: #f8fafc;
  }

  .net-desc {
    font-size: 0.8rem;
    color: #94a3b8;
  }

  .net-ip {
    font-family: monospace;
    font-size: 0.95rem;
    color: #60a5fa;
  }

  .net-gw {
    font-size: 0.8rem;
    color: #94a3b8;
  }

  .manual-section {
    border-top: 1px solid #334155;
    padding-top: 12px;
  }

  .toggle-manual {
    background: none;
    border: none;
    color: #60a5fa;
    cursor: pointer;
    font-size: 0.9rem;
    padding: 6px 0;
  }

  .manual-input {
    display: flex;
    gap: 8px;
    margin-top: 10px;
  }

  .manual-input input {
    flex: 1;
    padding: 10px 14px;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    color: #e2e8f0;
    font-family: monospace;
    font-size: 0.95rem;
  }

  .manual-input input:focus {
    outline: none;
    border-color: #60a5fa;
  }

  .btn-scan {
    padding: 10px 24px;
    background: #3b82f6;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
  }

  .btn-scan:hover {
    background: #2563eb;
  }
</style>
