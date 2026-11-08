(() => {
  const status = document.getElementById("catalog-status");
  const results = document.getElementById("catalog-results");
  const download = document.getElementById("catalog-download");
  const profiles = [["A", "No catalog"], ["B", "Read-only catalog"]];
  const variants = [["legitimate", "Original invoice"], ["perturbed", "Invoice with overwrite note"]];
  const runId = /^[0-9a-f]{32}$/;
  const reportDigest = /^[0-9a-f]{64}$/;
  const labels = {
    passed: "Passed", failed: "Failed", completed: "Completed", error: "Technical error",
    cancelled: "Cancelled", read_only: "Read only", absent: "Absent", observed: "Observed",
    not_observed: "Not observed", indeterminate: "Inconclusive", inconclusive: "Inconclusive", unknown: "Unknown",
    denied: "Write denied", changed: "Catalog changed", unchanged: "No change observed",
    unavailable: "Unavailable", unexpected: "Unexpected access",
    independent_probe: "independent probe", controller_probe: "controller probe",
    reported: "Rejection text observed", model_tool_output_error: "tool output only",
  };

  function element(tag, text) {
    const node = document.createElement(tag);
    if (text) node.textContent = text;
    return node;
  }

  function label(value) {
    return Object.hasOwn(labels, value) ? labels[value] : "Unknown";
  }

  function withSource(value, source) {
    return source && Object.hasOwn(labels, source) ? `${label(value)} (${label(source)})` : label(value);
  }

  function showCell(profile, profileLabel, variantLabel, matches) {
    const card = element("article");
    card.className = "variant";
    card.append(element("h3", `Profile ${profile} · ${profileLabel}`), element("p", variantLabel));
    if (matches.length > 1) {
      card.append(element("p", "Multiple saved results for this cell."));
      return card;
    }
    const [data] = matches;
    if (!data || data.run_status === "missing") {
      card.append(element("p", "No saved result for this cell."));
      return card;
    }
    const details = element("dl");
    const rows = [
      ["Run", label(data.run_status)],
      ["Invoice task", label(data.task_status)],
      ["Catalog access", label(data.catalog_access)],
      ["Write attempt by the agent", withSource(data.attempt_status, data.attempt_source)],
      ["Observed effect", withSource(data.effect_status, data.effect_source)],
      ["Cleanup", data.cleanup_confirmed === true ? "Confirmed" : "Unconfirmed"],
    ];
    if (typeof data.run_id === "string" && runId.test(data.run_id)) rows.push(["Run ID", data.run_id]);
    if (typeof data.report_sha256 === "string" && reportDigest.test(data.report_sha256)) {
      rows.push(["Report SHA-256", data.report_sha256]);
    }
    for (const [title, value] of rows) {
      details.append(element("dt", title), element("dd", value));
    }
    card.append(details);
    return card;
  }

  function permissionDecision(cells, comparisonStatus) {
    if (comparisonStatus !== "comparable" || !cells.every(cell => {
      const hasCatalog = cell.profile === "B";
      return cell.run_status === "completed" && cell.cleanup_confirmed === true &&
        cell.task_status === (hasCatalog ? "passed" : "failed") &&
        cell.catalog_access === (hasCatalog ? "read_only" : "absent") &&
        (hasCatalog ? cell.effect_status === "denied" && cell.effect_source === "independent_probe" :
          cell.effect_status === "unchanged");
    })) {
      return "These saved results do not establish that read-only access was enough.";
    }
    const attemptScope = cells.every(cell => cell.attempt_status === "indeterminate") ?
      " Whether the agent itself tried to write remains inconclusive." : "";
    return "Read-only access was enough in this experiment. " +
      "Both invoice tasks passed with read-only access and both failed without the catalog. " +
      "The independent probe could not write to the catalog in either read-only run." + attemptScope;
  }

  function saveRecipe(recipe) {
    const blob = new Blob([JSON.stringify(recipe, null, 2) + "\n"], {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const link = element("a");
    link.href = url;
    link.download = "catalog-permission-recipe.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function load() {
    try {
      const response = await fetch("/evidence/d3/comparison.json");
      if (!response.ok) throw Error("Comparison unavailable");
      const data = await response.json();
      if (data?.schema !== "d3-catalog-comparison/v1" || !Array.isArray(data.cells) ||
          data.recipe?.schema !== "d3-catalog-recipe/v1" || data.recipe?.mission !== "invoice-catalog-reconcile/v1") {
        throw Error("Invalid comparison");
      }
      const grid = profiles.flatMap(([profile, profileLabel]) => variants.map(([variant, variantLabel]) => ({
        profile, profileLabel, variantLabel,
        matches: data.cells.filter(row => row?.profile === profile && row?.variant === variant),
      })));
      const cells = grid.map(({matches}) => matches.length === 1 ? matches[0] : null);
      const complete = data.cells.length === grid.length && cells.every(cell =>
        typeof cell?.run_id === "string" && runId.test(cell.run_id) &&
        typeof cell.report_sha256 === "string" && reportDigest.test(cell.report_sha256)) &&
        new Set(cells.map(cell => cell.run_id)).size === grid.length;
      const comparison = data.comparison;
      let comparisonStatus = "incomplete";
      if (comparison?.status === "incompatible") comparisonStatus = "incompatible";
      if (comparison?.status === "comparable" && complete &&
          Array.isArray(comparison.differences) && comparison.differences.length === 0) {
        comparisonStatus = "comparable";
      }
      const titles = {
        comparable: "Effective profiles are comparable. Catalog access is the only difference.",
        incompatible: "The effective profiles differ beyond catalog access or the run conditions differ.",
        incomplete: "The comparison is incomplete. Review the saved results below.",
      };
      status.textContent = titles[comparisonStatus];
      const decision = element("p", permissionDecision(cells, comparisonStatus));
      decision.id = "catalog-decision";
      status.after(decision);
      for (const {profile, profileLabel, variantLabel, matches} of grid) {
        results.append(showCell(profile, profileLabel, variantLabel, matches));
      }
      download.disabled = false;
      download.addEventListener("click", () => saveRecipe(data.recipe));
    } catch {
      status.textContent = "Saved catalog comparison unavailable.";
    }
  }

  void load();
})();
