<script>
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import cytoscape from "cytoscape";
  import coseBilkent from "cytoscape-cose-bilkent";
  import dagre from "cytoscape-dagre";
  import DevicePanel from "./lib/components/DevicePanel.svelte";
  import Toolbar from "./lib/components/Toolbar.svelte";
  import StatusBar from "./lib/components/StatusBar.svelte";
  import NetworkSelector from "./lib/components/NetworkSelector.svelte";
  import { deviceStyles, edgeStyles } from "./lib/graph/styles";
  import { getIconForType } from "./lib/icons/registry";

  cytoscape.use(coseBilkent);
  cytoscape.use(dagre);

  let cy;
  let graphEl;
  let devices = [];
  let selectedDevice = null;
  let scanning = false;
  let scanSubnet = "192.168.1.0/24";
  let layoutMode = "cose";
  let networks = [];
  let showSelector = true;
  let discovering = true;

  onMount(() => {
    initGraph();
    discoverNetworks();
  });

  async function discoverNetworks() {
    discovering = true;
    try {
      networks = await invoke("discover_networks");
    } catch (e) {
      console.error("Discover error:", e);
      networks = [];
    } finally {
      discovering = false;
    }
  }

  function onNetworkSelect(e) {
    scanSubnet = e.detail.subnet;
    showSelector = false;
    doScan();
  }

  function initGraph() {
    cy = cytoscape({
      container: graphEl,
      style: [...deviceStyles, ...edgeStyles],
      layout: { name: "cose-bilkent", animate: true, animationDuration: 800 },
      wheelSensitivity: 0.3,
      minZoom: 0.2,
      maxZoom: 3,
    });

    cy.on("tap", "node", (evt) => {
      const node = evt.target;
      selectedDevice = devices.find((d) => d.id === node.data("id"));
    });

    cy.on("tap", (evt) => {
      if (evt.target === cy) selectedDevice = null;
    });
  }

  function updateGraph(data) {
    devices = data.devices;
    cy.elements().remove();

    const nodes = data.devices.map((d) => ({
      data: {
        id: d.id,
        label: d.hostname || d.ip,
        type: d.type,
        status: d.status,
        ip: d.ip,
        mac: d.mac,
      },
    }));

    const edges = (data.edges || []).map((e) => ({
      data: {
        id: `${e.source}-${e.target}`,
        source: e.source,
        target: e.target,
        type: e.type || "direct",
      },
    }));

    cy.add(nodes);
    cy.add(edges);
    cy.layout({ name: layoutMode === "cose" ? "cose-bilkent" : "dagre", animate: true }).run();
    cy.fit(undefined, 60);
  }

  async function doScan() {
    scanning = true;
    try {
      const data = await invoke("scan_network", { subnet: scanSubnet });
      updateGraph(data);
    } catch (e) {
      console.error("Scan error:", e);
    } finally {
      scanning = false;
    }
  }

  function toggleLayout() {
    layoutMode = layoutMode === "cose" ? "dagre" : "cose";
    cy.layout({ name: layoutMode === "cose" ? "cose-bilkent" : "dagre", animate: true }).run();
  }

  function exportImage(format) {
    const blob = format === "png" ? cy.png({ full: true, bg: "#0f172a" }) : cy.svg({ full: true, bg: "#0f172a" });
    const url = URL.createObjectURL(new Blob([blob]));
    const a = document.createElement("a");
    a.href = url;
    a.download = `netmap.${format}`;
    a.click();
  }
</script>

<div class="app">
  {#if showSelector}
    <NetworkSelector {networks} scanning={discovering} on:select={onNetworkSelect} />
  {/if}

  <Toolbar
    bind:scanSubnet
    {scanning}
    {layoutMode}
    onScan={doScan}
    onToggleLayout={toggleLayout}
    onExport={exportImage}
    onChangeNetwork={() => { showSelector = true; discoverNetworks(); }}
  />

  <main class="main">
    <div class="graph-container" bind:this={graphEl} />

    {#if selectedDevice}
      <DevicePanel device={selectedDevice} onClose={() => (selectedDevice = null)} />
    {/if}
  </main>

  <StatusBar deviceCount={devices.length} {scanning} />
</div>

<style>
  :global(*) {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  :global(body) {
    font-family: "Inter", sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    overflow: hidden;
  }

  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .main {
    flex: 1;
    display: flex;
    position: relative;
    overflow: hidden;
  }

  .graph-container {
    flex: 1;
    background: radial-gradient(ellipse at center, #1e293b 0%, #0f172a 70%);
  }
</style>
