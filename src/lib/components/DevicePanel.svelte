<script>
  export let device = null;
  export let onClose;

  $: ports = device?.ports || [];
  $: typeLabel = typeLabels[device?.type] || "Неизвестно";
  $: statusColor = statusColors[device?.status] || "#94a3b8";

  const typeLabels = {
    workstation: "Рабочая станция",
    server: "Сервер",
    router: "Роутер",
    switch: "Свитч",
    printer: "Принтер",
    camera: "Камера",
    iot: "IoT-устройство",
    unknown: "Неизвестно",
  };

  const statusColors = {
    online: "#22c55e",
    offline: "#ef4444",
    unknown: "#eab308",
  };
</script>

{#if device}
  <aside class="panel">
    <div class="panel-header">
      <h2>Устройство</h2>
      <button on:click={onClose} class="close-btn">✕</button>
    </div>

    <div class="device-icon" style="border-color: {statusColor}">
      <img src="/icons/{device.type || 'unknown'}.svg" alt={typeLabel} class="icon" />
    </div>

    <div class="device-info">
      <div class="info-row">
        <span class="label">IP</span>
        <span class="value mono">{device.ip}</span>
      </div>
      <div class="info-row">
        <span class="label">MAC</span>
        <span class="value mono">{device.mac}</span>
      </div>
      {#if device.vendor}
        <div class="info-row">
          <span class="label">Производитель</span>
          <span class="value">{device.vendor}</span>
        </div>
      {/if}
      {#if device.hostname}
        <div class="info-row">
          <span class="label">Имя</span>
          <span class="value">{device.hostname}</span>
        </div>
      {/if}
      <div class="info-row">
        <span class="label">Тип</span>
        <span class="value">{typeLabel}</span>
      </div>
      <div class="info-row">
        <span class="label">Статус</span>
        <span class="value" style="color: {statusColor}">
          {device.status === "online" ? "🟢 Онлайн" : device.status === "offline" ? "🔴 Офлайн" : "🟡 Неизвестно"}
        </span>
      </div>
      {#if device.os}
        <div class="info-row">
          <span class="label">ОС</span>
          <span class="value">{device.os}</span>
        </div>
      {/if}
    </div>

    {#if ports.length > 0}
      <div class="ports-section">
        <h3>Открытые порты</h3>
        <div class="ports-list">
          {#each ports as port}
            <div class="port-row">
              <span class="port-num">{port.port}/{port.protocol}</span>
              <span class="port-service">{port.service || "—"}</span>
              <span class="port-state {port.state}">{port.state}</span>
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </aside>
{/if}

<style>
  .panel {
    width: 300px;
    background: #1e293b;
    border-left: 1px solid #334155;
    overflow-y: auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .panel-header h2 {
    font-size: 16px;
    font-weight: 600;
    color: #f1f5f9;
  }

  .close-btn {
    background: none;
    border: none;
    color: #64748b;
    font-size: 18px;
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 4px;
  }

  .close-btn:hover {
    background: #334155;
    color: #e2e8f0;
  }

  .device-icon {
    width: 96px;
    height: 96px;
    margin: 0 auto;
    border: 3px solid #475569;
    border-radius: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0f172a;
  }

  .icon {
    width: 56px;
    height: 56px;
  }

  .device-info {
    display: flex;
    flex-direction: column;
    gap: 8px;
    background: #0f172a;
    border-radius: 8px;
    padding: 12px;
  }

  .info-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 13px;
  }

  .label {
    color: #64748b;
    font-weight: 500;
  }

  .value {
    color: #e2e8f0;
    max-width: 170px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .mono {
    font-family: "SF Mono", "Fira Code", monospace;
    font-size: 12px;
  }

  .ports-section h3 {
    font-size: 14px;
    font-weight: 600;
    color: #94a3b8;
    margin-bottom: 8px;
  }

  .ports-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .port-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    background: #0f172a;
    border-radius: 6px;
    font-size: 12px;
  }

  .port-num {
    color: #38bdf8;
    font-family: monospace;
    font-weight: 600;
  }

  .port-service {
    color: #94a3b8;
    flex: 1;
  }

  .port-state {
    font-weight: 600;
    text-transform: uppercase;
    font-size: 10px;
    padding: 2px 6px;
    border-radius: 4px;
  }

  .port-state.open {
    color: #22c55e;
    background: #1a3a2a;
  }

  .port-state.filtered {
    color: #eab308;
    background: #3a351a;
  }
</style>
