let severityChart = null;
let alertChart = null;

async function startScan(target) {

    const loading =
        document.getElementById("loading");

    const currentTarget =
        document.getElementById("current-target");

    loading.style.display = "block";

    currentTarget.innerText = target;

    try {

        const response =
            await fetch(`/scan/${target}`);

        const data =
            await response.json();

        if (!data.success) {

            alert(data.error);

            loading.style.display = "none";

            return;
        }

        updateMetrics(
            data.summary.severity
        );

        updateFindings(
            data.findings
        );

        updateHistory(
            data.history
        );

        updateTriage(
            data.triage.top_findings
        );

        renderSeverityChart(
            data.summary.severity
        );

        renderAlertChart(
            data.charts.top_alerts
        );

    } catch(err) {

        console.error(err);

        alert(
            "Scan failed"
        );
    }

    loading.style.display = "none";
}

function updateMetrics(severity) {

    document.getElementById(
        "high-count"
    ).innerText =
        severity.High || 0;

    document.getElementById(
        "medium-count"
    ).innerText =
        severity.Medium || 0;

    document.getElementById(
        "low-count"
    ).innerText =
        severity.Low || 0;

    document.getElementById(
        "info-count"
    ).innerText =
        severity.Informational || 0;
}

function updateFindings(findings) {

    const body =
        document.getElementById(
            "findings-body"
        );

    body.innerHTML = "";

    findings.forEach(finding => {

        body.innerHTML += `
        <tr>
            <td>${finding.alert}</td>
            <td>${finding.risk}</td>
            <td>${finding.confidence}</td>
            <td>${finding.cweid}</td>
        </tr>
        `;
    });
}

function updateHistory(history) {

    const body =
        document.getElementById(
            "history-body"
        );

    body.innerHTML = "";

    history
        .slice()
        .reverse()
        .forEach(scan => {

        body.innerHTML += `
        <tr>
            <td>${scan.timestamp}</td>
            <td>${scan.target}</td>
            <td>${scan.total_alerts}</td>
            <td>${scan.duration}s</td>
        </tr>
        `;
    });
}

function updateTriage(findings) {

    const body =
        document.getElementById(
            "triage-body"
        );

    body.innerHTML = "";

    findings.forEach(finding => {

        body.innerHTML += `
        <tr onclick='showFinding(${JSON.stringify(finding)})'>

            <td>
                ${finding.priority}
            </td>

            <td>
                ${finding.alert}
            </td>

            <td>
                ${finding.risk}
            </td>

            <td>
                ${finding.count}
            </td>

        </tr>
        `;
    });
}

function showFinding(finding) {

    const modal =
        document.getElementById(
            "finding-modal"
        );

    const title =
        document.getElementById(
            "modal-title"
        );

    const details =
        document.getElementById(
            "modal-details"
        );

    title.innerText =
        finding.alert;

    details.innerHTML = `

        <p>
            <strong>Risk:</strong>
            ${finding.risk}
        </p>

        <br>

        <p>
            <strong>Priority:</strong>
            ${finding.priority}
        </p>

        <br>

        <p>
            <strong>Recommendation:</strong>
            ${finding.recommendation}
        </p>

        <br>

        <h3>
            Affected URLs
        </h3>

        <ul>

            ${finding.affected_urls
                .map(
                    url =>
                    `<li>${url}</li>`
                )
                .join("")
            }

        </ul>
    `;

    modal.style.display = "block";
}

document
    .getElementById(
        "close-modal"
    )
    .addEventListener(
        "click",
        () => {

            document
                .getElementById(
                    "finding-modal"
                )
                .style.display =
                    "none";
        }
    );

window.onclick =
    function(event) {

        const modal =
            document.getElementById(
                "finding-modal"
            );

        if (
            event.target === modal
        ) {

            modal.style.display =
                "none";
        }
    };

function renderSeverityChart(data) {

    const ctx =
        document
            .getElementById(
                "severityChart"
            );

    if (
        severityChart
    ) {

        severityChart.destroy();
    }

    severityChart =
        new Chart(ctx, {

        type: "doughnut",

        data: {

            labels:
                Object.keys(data),

            datasets: [{

                data:
                    Object.values(data)
            }]
        }
    });
}

function renderAlertChart(data) {

    const ctx =
        document
            .getElementById(
                "alertChart"
            );

    if (
        alertChart
    ) {

        alertChart.destroy();
    }

    alertChart =
        new Chart(ctx, {

        type: "bar",

        data: {

            labels:
                Object.keys(data),

            datasets: [{

                data:
                    Object.values(data)
            }]
        }
    });
}