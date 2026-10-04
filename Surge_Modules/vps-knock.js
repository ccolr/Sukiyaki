// Surge generic script: send one knockd sequence directly to one VPS.

(function () {
    "use strict";

    const KNOCK_GAP_MILLISECONDS = 120;
    const FINISH_DELAY_MILLISECONDS = 1500;
    const MAX_KNOCK_PORTS = 5;
    let completed = false;

    function finish(title, content, style) {
        if (completed) return;
        completed = true;
        $done({ title: title, content: content, style: style });
    }

    function safeDecode(value) {
        try {
            return decodeURIComponent(String(value).replace(/\+/g, " "));
        } catch (error) {
            return String(value);
        }
    }

    function parseArguments(rawArgument) {
        const result = {};
        String(rawArgument || "").split("&").forEach(function (pair) {
            const separatorIndex = pair.indexOf("=");
            if (separatorIndex <= 0) return;
            result[safeDecode(pair.slice(0, separatorIndex))] =
                safeDecode(pair.slice(separatorIndex + 1));
        });
        return result;
    }

    function parsePorts(value, label) {
        const items = String(value || "")
            .split(/[|,]/)
            .map(function (item) { return item.trim(); })
            .filter(function (item) { return item.length > 0; });

        if (items.length === 0 || items.length > MAX_KNOCK_PORTS) {
            throw new Error(label + " must contain 1-" + MAX_KNOCK_PORTS + " ports.");
        }

        const ports = items.map(function (item) {
            if (!/^\d+$/.test(item)) {
                throw new Error(label + " contains an invalid port: " + item);
            }
            const port = Number(item);
            if (port < 1 || port > 65535) {
                throw new Error(label + " contains a port outside 1-65535: " + item);
            }
            return port;
        });

        if (new Set(ports).size !== ports.length) {
            throw new Error(label + " cannot contain duplicate ports.");
        }
        return ports;
    }

    function normalizeHost(value) {
        const host = String(value || "").trim();
        if (!host) throw new Error("VPS host cannot be empty.");
        if (/^https?:\/\//i.test(host) || /[\/?#@\s]/.test(host)) {
            throw new Error("VPS host must not contain a scheme, path, credentials, or spaces.");
        }
        if (host.indexOf(":") >= 0) {
            if (/^\[[0-9a-fA-F:.]+\]$/.test(host)) return host;
            if (/^[0-9a-fA-F:.]+$/.test(host)) return "[" + host + "]";
            throw new Error("VPS host must not include a port.");
        }
        return host;
    }

    function validateRetrySafety(openPorts, closePorts) {
        const openTerminal = openPorts[openPorts.length - 1];
        const closeTerminal = closePorts[closePorts.length - 1];

        if (closePorts.indexOf(openTerminal) !== -1) {
            throw new Error(
                "Open terminal port " + openTerminal +
                " must not appear in the close sequence."
            );
        }
        if (openPorts.indexOf(closeTerminal) !== -1) {
            throw new Error(
                "Close terminal port " + closeTerminal +
                " must not appear in the open sequence."
            );
        }
    }

    const args = parseArguments(typeof $argument === "string" ? $argument : "");
    const action = args.action;
    const actionLabel = action === "open" ? "Open" : "Close";
    const name = String(args.name || args.host || "VPS").trim();
    const panelTitle = name + " Knock " + actionLabel;

    if (typeof $trigger === "string" && $trigger === "auto-interval") {
        finish(panelTitle, "Automatic refresh is disabled. Run this action manually.", "alert");
        return;
    }
    if (action !== "open" && action !== "close") {
        finish("VPS Knockd", "Configuration error: action must be open or close.", "error");
        return;
    }

    let host;
    let openPorts;
    let closePorts;

    try {
        host = normalizeHost(args.host);
        openPorts = parsePorts(args.open, "Open sequence");
        closePorts = parsePorts(args.close, "Close sequence");
        validateRetrySafety(openPorts, closePorts);
    } catch (error) {
        finish(panelTitle, "Configuration error: " + error.message, "error");
        return;
    }

    const ports = action === "open" ? openPorts : closePorts;
    const terminalPort = ports[ports.length - 1];

    ports.forEach(function (port, index) {
        setTimeout(function () {
            console.log(
                "[vps-knock] action=" + action +
                " sending=" + (index + 1) + "/" + ports.length +
                " port=" + port
            );
            $httpClient.head({
                url: "http://" + host + ":" + port + "/",
                timeout: 1,
                policy: "DIRECT",
                "auto-redirect": false
            }, function () {});
        }, index * KNOCK_GAP_MILLISECONDS);
    });

    setTimeout(function () {
        finish(
            name + " Knock " + actionLabel + " Sent",
            [
                "Target: " + host,
                "Sequence: " + ports.join(" → "),
                "Terminal port: " + terminalPort,
                "Route: DIRECT"
            ].join("\n"),
            "good"
        );
    }, (ports.length - 1) * KNOCK_GAP_MILLISECONDS + FINISH_DELAY_MILLISECONDS);
})();
