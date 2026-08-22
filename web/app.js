const $ = (selector) => document.querySelector(selector);

const labels = {
  ready: "Eligible to approve",
  review: "Human review required",
  missing: "Submission blocked",
};

function renderAudit(data) {
  $("#submission-name").textContent = data.name || "Global Impact Grant — Final Package";
  $("#hours").textContent = Math.floor(data.hours_remaining);
  $("#confidence").textContent = `${data.confidence}%`;
  $("#score-ring").style.setProperty("--score", `${data.confidence * 3.6}deg`);
  $("#state").textContent = labels[data.state];
  $("#summary").textContent = data.agent_summary;
  $("#ready-count").textContent = data.ready;
  $("#review-count").textContent = data.review;
  $("#missing-count").textContent = data.missing;
  $("#total-count").textContent = data.total;

  $("#artifact-list").innerHTML = data.artifacts.map((artifact) => `
    <div class="artifact ${artifact.state}">
      <div><strong>${artifact.label}</strong><small>${artifact.evidence || "No verified evidence attached"}</small></div>
      <span class="pill">${artifact.state}</span>
    </div>
  `).join("");

  $("#action-list").innerHTML = data.actions.map((action) => `
    <li><strong>${action.title}</strong><span>${action.reason}${action.requires_human ? " · Human decision" : ""}</span></li>
  `).join("") || "<li><strong>Hold for final approval</strong><span>No corrective action is required.</span></li>";
}

async function runAudit() {
  const button = $("#run-audit");
  button.disabled = true;
  button.firstChild.textContent = "Auditing evidence ";
  try {
    const response = await fetch("/api/demo");
    if (!response.ok) throw new Error("Audit failed");
    const data = await response.json();
    renderAudit({ ...data, name: "Global Impact Grant — Final Package" });
    document.querySelector(".dashboard").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    $("#summary").textContent = "The audit endpoint is unavailable. No readiness claim has been made.";
    $("#state").textContent = "Fail closed";
  } finally {
    button.disabled = false;
    button.firstChild.textContent = "Run live audit ";
  }
}

$("#run-audit").addEventListener("click", runAudit);
fetch("/api/demo").then((response) => response.json()).then((data) => renderAudit({ ...data, name: "Global Impact Grant — Final Package" }));
