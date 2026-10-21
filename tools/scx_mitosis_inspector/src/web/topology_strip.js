// Live cell ownership shown as cell rows and LLC columns.
(function (root, factory) {
  const api = factory();
  root.MitosisTopologyStrip = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  const rendered = new WeakMap();
  const gridSelections = new WeakMap();
  const percent = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });

  function buildModel(topology, cpuCells, metrics) {
    const cells = Object.entries(metrics ?? {}).map(([id, value]) => ({
      id: Number(id), path: value.cgroup_path ?? "", cpus: [],
    })).sort((a, b) => a.id - b.id);
    const byCell = new Map(cells.map(cell => [cell.id, cell]));
    const groups = new Map();
    const cpus = [...(topology?.cpus ?? [])].sort((a, b) => a.cpu - b.cpu);
    let unknownCount = 0;
    for (const cpu of cpus) {
      if (!groups.has(cpu.llc)) groups.set(cpu.llc, { id: cpu.llc, cpus: [], owners: new Map(), cores: new Map() });
      const group = groups.get(cpu.llc);
      group.cpus.push(cpu.cpu);
      const identified = cpu.core_topology_available !== false
        && Number.isInteger(cpu.package) && Number.isInteger(cpu.core);
      const core = identified
        ? `${cpu.package}/${cpu.core}` : `cpu:${cpu.cpu}`;
      if (!group.cores.has(core)) group.cores.set(core, {
        package: identified ? cpu.package : null,
        id: identified ? cpu.core : null,
        cpus: [],
      });
      group.cores.get(core).cpus.push(cpu.cpu);
      const owner = cpuCells?.[cpu.cpu];
      const cell = Number.isInteger(owner) && byCell.has(owner) ? owner : null;
      if (cell === null) unknownCount += 1;
      else byCell.get(cell).cpus.push(cpu.cpu);
      if (!group.owners.has(cell)) group.owners.set(cell, []);
      group.owners.get(cell).push(cpu.cpu);
    }
    const llcs = [...groups.values()].map(group => {
      const cores = [...group.cores.values()];
      const threads = Math.max(...cores.map(core => core.cpus.length));
      const grid = [];
      // Eight physical cores per block; the next row contains their SMT siblings.
      // Null padding is empty space, distinct from a CPU whose owner is unknown.
      for (let start = 0; start < cores.length; start += 8) {
        for (let thread = 0; thread < threads; thread += 1) {
          for (let column = 0; column < 8; column += 1) {
            grid.push(cores[start + column]?.cpus[thread] ?? null);
          }
        }
      }
      return {
        id: group.id, cpus: group.cpus, cores, grid,
        segments: [...group.owners].sort(([a], [b]) => (a ?? Infinity) - (b ?? Infinity))
          .map(([cell, ids]) => ({ cell, cpus: ids, share: ids.length / group.cpus.length })),
      };
    }).sort((a, b) => a.id - b.id);
    return { llcs, cells, cpuCount: cpus.length, unknownCount };
  }

  function cpuRanges(cpus) {
    const ranges = [];
    for (let index = 0; index < cpus.length; index += 1) {
      const start = cpus[index];
      let end = start;
      while (cpus[index + 1] === end + 1) end = cpus[++index];
      ranges.push(start === end ? String(start) : `${start}-${end}`);
    }
    return ranges.join(",");
  }

  function render(section, topology, snapshot, cellColors) {
    const status = section.querySelector("#cpuTopologyStatus");
    const model = buildModel(topology, snapshot?.cpu_cells_error ? null : snapshot?.cpu_cells, snapshot?.metrics?.cells);
    const head = section.querySelector("#cellPlacementMatrixHead");
    const body = section.querySelector("#cellPlacementMatrixBody");
    if (!model.cpuCount) {
      status.textContent = "Waiting for CPU topology";
      head.replaceChildren();
      body.replaceChildren();
      section.querySelector("#cellCpusetNumeric").replaceChildren();
      section.querySelector("#cellCpusetLlc").replaceChildren();
      rendered.delete(section);
      gridSelections.delete(section);
      return;
    }
    status.textContent = `${model.cpuCount} logical CPUs · ${model.llcs.length} LLCs · ${model.cells.length} cells`;
    if (snapshot?.cpu_cells_error) status.textContent += ` · Ownership unavailable: ${snapshot.cpu_cells_error}`;
    else if (model.unknownCount) status.textContent += ` · ${model.unknownCount} CPU owners unavailable`;
    const signature = JSON.stringify(model);
    if (rendered.get(section) === signature) return;
    rendered.set(section, signature);
    const color = cell => cellColors[cell % cellColors.length];
    section.querySelector("#cellPlacementMatrix").setAttribute("style", `min-width: ${Math.max(480, model.llcs.length * 80 + 280)}px`);

    function element(tag, className, text) {
      const node = document.createElement(tag);
      if (className) node.className = className;
      if (text !== undefined) node.textContent = text;
      return node;
    }

    const header = element("tr");
    for (const label of ["Cell", ...model.llcs.map(llc => `LLC ${llc.id}`), "Total"]) {
      const th = element("th", "", label);
      th.setAttribute("scope", "col");
      header.append(th);
    }
    model.llcs.forEach((llc, index) => {
      const th = header.children[index + 1];
      th.append(element("small", "", `${llc.cpus.length} CPUs`));
      th.title = `LLC ${llc.id}\nCPUs ${cpuRanges(llc.cpus)}`;
    });
    head.replaceChildren(header);

    function row(cell) {
      const unknown = cell.id === null;
      const tr = element("tr", unknown ? "cell-placement-unknown" : "");
      tr.dataset.cell = cell.id ?? "unknown";
      if (!unknown) tr.setAttribute("style", `--owner: ${color(cell.id)}`);
      const owner = unknown ? "Ownership unavailable" : `Cell ${cell.id} · ${cell.path || "cgroup unavailable"}`;
      const th = element("th");
      th.setAttribute("scope", "row");
      th.setAttribute("tabindex", "0");
      th.title = `${owner}\nCPUs ${cpuRanges(cell.cpus) || (model.unknownCount ? "unavailable" : "none")}`;
      const label = element("span", "cell-placement-owner");
      const swatch = element("span", "series-swatch");
      if (!unknown) swatch.setAttribute("style", `background-color: ${color(cell.id)}`);
      swatch.setAttribute("aria-hidden", "true");
      const name = unknown ? "Unavailable" : cell.path === "/" ? "Root" : cell.path.split("/").at(-1).replace(/\.service$/, "") || "cgroup unavailable";
      const text = element("span", "cell-placement-owner-text");
      text.append(element("span", "cell-placement-name", name),
        element("span", "cell-placement-id", unknown ? "CPU owners unknown" : `Cell ${cell.id}`));
      label.append(swatch, text);
      th.append(label);
      tr.append(th);
      for (const llc of model.llcs) {
        const segment = llc.segments.find(part => part.cell === cell.id);
        const ids = segment?.cpus ?? [];
        const share = ids.length / llc.cpus.length;
        const unavailable = llc.segments.find(part => part.cell === null)?.cpus.length ?? 0;
        const td = element("td");
        td.dataset.llc = llc.id;
        td.dataset.count = ids.length;
        td.dataset.share = share;
        let detail = `LLC ${llc.id} · ${owner}\n${ids.length} of ${llc.cpus.length} CPUs (${percent.format(share * 100)}%)\nCPUs ${cpuRanges(ids) || "none observed"}`;
        if (!unknown && unavailable) detail += `\n${unavailable} CPU owners unavailable in this LLC`;
        td.title = detail;
        td.setAttribute("aria-label", detail);
        if (ids.length) {
          td.setAttribute("tabindex", "0");
          const track = element("div", "cell-placement-track");
          track.setAttribute("aria-hidden", "true");
          const fill = element("span", "cell-placement-fill");
          fill.setAttribute("style", `width: ${share * 100}%`);
          track.append(fill);
          td.append(element("span", "cell-placement-count", ids.length), track);
        } else td.append(element("span", "cell-placement-empty", "—"));
        tr.append(td);
      }
      const total = element("td", "cell-placement-total",
        !unknown && !cell.cpus.length && model.unknownCount ? "—" : cell.cpus.length);
      total.dataset.count = cell.cpus.length;
      total.title = `${owner}\n${cell.cpus.length} observed assigned CPUs\nCPUs ${cpuRanges(cell.cpus) || "none observed"}`;
      if (!unknown && model.unknownCount) total.title += `\n${model.unknownCount} CPU owners unavailable on this host`;
      tr.append(total);
      return tr;
    }
    const cells = model.cells.slice();
    if (model.unknownCount) cells.push({ id: null,
      cpus: model.llcs.flatMap(llc => llc.segments.find(part => part.cell === null)?.cpus ?? []).sort((a, b) => a - b) });
    body.replaceChildren(...cells.map(row));

    const slots = model.llcs.flatMap(llc => llc.segments.flatMap(segment =>
      segment.cpus.map(cpu => ({ cpu, llc: llc.id, owner: segment.cell }))));
    for (const [order, id] of [["numeric", "cellCpusetNumeric"]]) {
      const ordered = slots.slice().sort((a, b) =>
        a.cpu - b.cpu);
      const axis = element("div", `cpuset-axis cpuset-axis-${order}`);
      axis.setAttribute("aria-hidden", "true");
      const indices = [...new Set(Array.from({ length: 5 }, (_, index) =>
        Math.round(index * (ordered.length - 1) / 4)))];
      for (const index of indices) {
        const label = element("span", "cpuset-axis-label", ordered[index].cpu);
        label.setAttribute("style", `left: ${ordered.length > 1 ? index / (ordered.length - 1) * 100 : 0}%`);
        axis.append(label);
      }
      const bars = cells.map(cell => {
        const unknown = cell.id === null;
        const owner = unknown ? "CPU ownership unavailable" : `Cell ${cell.id} · ${cell.path || "cgroup unavailable"}`;
        const cpusetRow = element("div", "cpuset-row");
        cpusetRow.dataset.cell = cell.id ?? "unknown";
        if (!unknown) cpusetRow.setAttribute("style", `--owner: ${color(cell.id)}`);
        const label = element("span", "cpuset-label", unknown ? "Unknown" : `Cell ${cell.id}`);
        label.title = owner;
        const bar = element("div", "cpuset-bar");
        const detail = `${owner}\n${unknown ? "CPUs with unknown owners" : "Assigned CPUs"}: ${cpuRanges(cell.cpus) || (model.unknownCount ? "unavailable" : "none")}`;
        bar.setAttribute("role", "img");
        bar.setAttribute("aria-label", detail);
        bar.setAttribute("tabindex", "0");
        bar.title = detail;
        ordered.forEach((slot, index) => {
          const classes = ["cpuset-cpu"];
          if (slot.owner === cell.id) classes.push("cpuset-assigned");
          if (slot.owner === null) classes.push("cpuset-unknown");
          const block = element("span", classes.join(" "));
          block.dataset.cpu = slot.cpu;
          block.dataset.llc = slot.llc;
          block.setAttribute("aria-hidden", "true");
          block.title = `CPU ${slot.cpu} · LLC ${slot.llc}\n${slot.owner === null ? "Ownership unavailable" : `Cell ${slot.owner}`}\n${slot.owner === cell.id ? "Assigned to this cell" : slot.owner === null ? "Cell membership unavailable" : "Assigned to another cell"}`;
          bar.append(block);
        });
        const count = element("span", "cpuset-count",
          !unknown && !cell.cpus.length && model.unknownCount ? "—" : cell.cpus.length);
        count.title = unknown ? "CPUs with unavailable owners" : "Observed assigned logical CPUs";
        cpusetRow.append(label, bar, count);
        return cpusetRow;
      });
      section.querySelector(`#${id}`).replaceChildren(axis, ...bars);
    }

    const grid = section.querySelector("#cellCpusetLlc");
    const active = document.activeElement;
    const focusTarget = active && grid.contains(active)
      ? { cell: active.dataset.cell, llc: active.dataset.llc } : null;
    grid.setAttribute("style", `--llc-count: ${model.llcs.length}; min-width: ${Math.max(480, 152 + model.llcs.length * 84)}px`);
    grid.setAttribute("role", "table");
    grid.setAttribute("tabindex", "-1");
    grid.setAttribute("aria-label", "Assigned CPU membership by cell and LLC");
    const axis = element("div", "cpuset-grid-axis");
    axis.setAttribute("role", "row");
    const cellHeading = element("span", "", "Cell");
    cellHeading.setAttribute("role", "columnheader");
    const llcHeadings = element("div", "cpuset-grid-llcs");
    llcHeadings.setAttribute("role", "presentation");
    for (const llc of model.llcs) {
      const label = element("span", "", `LLC ${llc.id}`);
      label.dataset.llc = llc.id;
      label.setAttribute("role", "columnheader");
      const coreInfo = llc.cores.some(core => core.id === null)
        ? "Core topology incomplete" : `${llc.cores.length} physical cores`;
      label.title = `${llc.cpus.length} logical CPUs · ${coreInfo}\nIDs ${cpuRanges(llc.cpus)}`;
      llcHeadings.append(label);
    }
    const totalHeading = element("span", "cpuset-grid-total", "CPUs");
    totalHeading.setAttribute("role", "columnheader");
    axis.append(cellHeading, llcHeadings, totalHeading);

    const byCpu = new Map(slots.map(slot => [slot.cpu, slot]));
    let selected = gridSelections.get(section) ?? null;
    if (!cells.some(cell => (cell.id ?? "unknown") === selected)) {
      selected = null;
      gridSelections.delete(section);
    }
    const gridRows = [];
    function updateSelection() {
      for (const { key, node, button } of gridRows) {
        node.classList.toggle("cpuset-grid-muted", selected !== null && selected !== key);
        button.setAttribute("aria-pressed", String(selected === key));
      }
    }
    for (const cell of cells) {
      const unknown = cell.id === null;
      const key = cell.id ?? "unknown";
      const owner = unknown ? "CPU ownership unavailable" : `Cell ${cell.id} · ${cell.path || "cgroup unavailable"}`;
      const node = element("div", `cpuset-grid-row${unknown ? " cpuset-grid-unknown" : ""}`);
      node.dataset.cell = key;
      node.setAttribute("role", "row");
      node.setAttribute("style", `--owner: ${unknown ? "var(--text-muted)" : color(cell.id)}`);
      const label = element("span", "cpuset-grid-label");
      label.setAttribute("role", "rowheader");
      const button = element("button", "cpuset-grid-select");
      button.dataset.cell = key;
      button.setAttribute("type", "button");
      button.title = `${owner}\nClick to highlight this row`;
      const swatch = element("span", "series-swatch");
      swatch.setAttribute("aria-hidden", "true");
      button.append(swatch, element("span", "", unknown ? "Unknown" : `Cell ${cell.id}`));
      button.addEventListener("click", () => {
        selected = selected === key ? null : key;
        gridSelections.set(section, selected);
        updateSelection();
      });
      label.append(button);
      const groups = element("div", "cpuset-grid-groups");
      groups.setAttribute("role", "presentation");
      for (const llc of model.llcs) {
        const ids = llc.segments.find(segment => segment.cell === cell.id)?.cpus ?? [];
        const group = element("div", "cpuset-grid-cell");
        group.dataset.llc = llc.id;
        group.dataset.cell = key;
        group.dataset.count = ids.length;
        group.setAttribute("role", "cell");
        const inspect = element("button", "cpuset-grid-group");
        inspect.setAttribute("type", "button");
        inspect.setAttribute("tabindex", "0");
        inspect.dataset.cell = key;
        inspect.dataset.llc = llc.id;
        inspect.addEventListener("click", () => {
          selected = selected === key ? null : key;
          gridSelections.set(section, selected);
          updateSelection();
        });
        let detail = `${owner}\nLLC ${llc.id} · ${ids.length} of ${llc.cpus.length} CPUs (${percent.format(ids.length / llc.cpus.length * 100)}%)\nCPUs ${cpuRanges(ids) || "none observed"}`;
        const unavailable = llc.segments.find(segment => segment.cell === null)?.cpus.length ?? 0;
        if (!unknown && unavailable) detail += `\n${unavailable} CPU owners unavailable in this LLC`;
        inspect.title = detail;
        inspect.setAttribute("aria-label", detail);
        const dots = element("span", "cpuset-grid-dots");
        const threadRows = Math.max(...llc.cores.map(core => core.cpus.length));
        dots.setAttribute("style", `--smt-rows: ${threadRows}`);
        dots.setAttribute("aria-hidden", "true");
        const siblingContexts = [];
        const coreSlots = [...llc.cores, ...Array((8 - llc.cores.length % 8) % 8).fill(null)];
        for (const core of coreSlots) {
          if (core === null) {
            dots.append(element("span", "cpuset-core cpuset-core-padding"));
            continue;
          }
          const assigned = core.cpus.filter(cpu => byCpu.get(cpu).owner === cell.id).length;
          const classes = ["cpuset-core"];
          if (assigned) classes.push("cpuset-core-assigned");
          if (core.id === null) classes.push("cpuset-core-unidentified");
          const tile = element("span", classes.join(" "));
          tile.setAttribute("style", `--smt-rows: ${core.cpus.length}`);
          tile.dataset.core = core.id === null ? `cpu:${core.cpus[0]}` : `${core.package}/${core.id}`;
          const coreInfo = core.id === null ? "Core topology unavailable" : `Package ${core.package} · Core ${core.id}`;
          const siblingInfo = core.cpus.map(cpu => {
            const slot = byCpu.get(cpu);
            return `CPU ${cpu} · ${slot.owner === null ? "Ownership unavailable" : `Cell ${slot.owner}`}${!unknown && slot.owner === cell.id ? " · assigned to this row" : ""}`;
          }).join("\n");
          tile.title = `${coreInfo} · LLC ${llc.id}\n${siblingInfo}`;
          if (assigned && (core.id === null || core.cpus.some(cpu => byCpu.get(cpu).owner !== cell.id))) {
            siblingContexts.push(tile.title);
          }
          for (const cpu of core.cpus) {
            const slot = byCpu.get(cpu);
            const classes = ["cpuset-grid-cpu"];
            const foreign = !unknown && assigned > 0 && slot.owner !== null && slot.owner !== cell.id;
            if (slot.owner === cell.id) classes.push("cpuset-assigned");
            if (slot.owner === null) classes.push("cpuset-unknown");
            if (foreign) classes.push("cpuset-sibling-foreign");
            const dot = element("span", classes.join(" "));
            dot.dataset.cpu = cpu;
            dot.dataset.llc = llc.id;
            dot.dataset.owner = slot.owner ?? "unknown";
            if (foreign) dot.setAttribute("style", `--sibling-owner: ${color(slot.owner)}`);
            dot.title = tile.title;
            tile.append(dot);
          }
          dots.append(tile);
        }
        if (siblingContexts.length) detail += `\nSibling ownership for this row:\n${siblingContexts.join("\n")}`;
        inspect.title = detail;
        inspect.setAttribute("aria-label", detail);
        inspect.append(dots, element("span", "cpuset-grid-count", ids.length));
        group.append(inspect);
        groups.append(group);
      }
      const total = element("span", "cpuset-grid-total",
        !unknown && !cell.cpus.length && model.unknownCount ? "—" : cell.cpus.length);
      total.setAttribute("role", "cell");
      total.title = `${owner}\nObserved assigned CPUs: ${cpuRanges(cell.cpus) || "none observed"}`;
      node.append(label, groups, total);
      gridRows.push({ key, node, button });
    }
    updateSelection();
    grid.replaceChildren(axis, ...gridRows.map(row => row.node));
    if (focusTarget) {
      const row = gridRows.find(row => String(row.key) === String(focusTarget.cell));
      const target = focusTarget.llc === undefined ? row?.button
        : Array.from(row?.node.children[1].children ?? []).find(group => String(group.dataset.llc) === String(focusTarget.llc))?.children[0];
      (target ?? row?.button ?? grid).focus({ preventScroll: true });
    }
  }
  return { buildModel, render };
});
