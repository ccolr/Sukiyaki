// Surge generic script: sends one knockd port sequence to one VPS.

(function () {
    "use strict";

    // Keep the connection attempt shorter than the normal first TCP SYN
    // retransmission window. A knock is the initial connection attempt; an
    // HTTP response is neither required nor expected.
    const KNOCK_REQUEST_TIMEOUT_SECONDS = 0.5;
    const KNOCK_GAP_MILLISECONDS = 100;
    const MAX_KNOCK_PORTS = 5;
    let completed = false;

    function finish(title, content, style) {
        if (completed) return;
        completed = true;
        $done({
            title: title,
            content: content,
            style: style
        });
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
        if (typeof rawArgument !== "string" || rawArgument.length === 0) {
            return result;
        }

        rawArgument.split("&").forEach(function (pair) {
            const separatorIndex = pair.indexOf("=");
            if (separatorIndex <= 0) return;

            const key = safeDecode(pair.slice(0, separatorIndex));
            const value = safeDecode(pair.slice(separatorIndex + 1));
            result[key] = value;
        });

        return result;
    }

    function parsePorts(value) {
        const values = String(value || "")
            .split(/[|,]/)
            .map(function (item) { return item.trim(); })
            .filter(function (item) { return item.length > 0; });

        if (values.length === 0) {
            throw new Error("The knock sequence cannot be empty.");
        }
        if (values.length > MAX_KNOCK_PORTS) {
            throw new Error("The knock sequence supports up to " + MAX_KNOCK_PORTS + " ports.");
        }

        return values.map(function (value) {
            if (!/^\d+$/.test(value)) {
                throw new Error("The knock sequence contains an invalid port: " + value);
            }

            const port = Number(value);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                throw new Error("The knock port is outside 1-65535: " + value);
            }
            return port;
        });
    }

    function normalizeHost(value) {
        const host = String(value || "").trim();
        if (host.length === 0) {
            throw new Error("The VPS address cannot be empty.");
        }
        if (/^https?:\/\//i.test(host) || /[\/?#@\s]/.test(host)) {
            throw new Error("The VPS address cannot contain a scheme, path, credentials, or spaces: " + host);
        }
        if (host.indexOf("[") >= 0 || host.indexOf("]") >= 0) {
            if (/^\[[0-9a-fA-F:.]+\]$/.test(host)) {
                return host;
            }
            throw new Error("Invalid IPv6 address: " + host);
        }

        const colonCount = (host.match(/:/g) || []).length;
        if (colonCount === 1) {
            throw new Error("The VPS address cannot include a port: " + host);
        }
        if (colonCount > 1) {
            if (!/^[0-9a-fA-F:.]+$/.test(host)) {
                throw new Error("Invalid IPv6 address: " + host);
            }
            return "[" + host + "]";
        }
        return host;
    }

    const args = parseArguments(typeof $argument === "string" ? $argument : "");
    const action = args.action;
    const configuredName = String(args.name || "").trim() || String(args.host || "").trim() || "VPS";
    const actionLabel = action === "open" ? "Open" : "Close";
    const panelTitle = configuredName + " Knock " + actionLabel;
    const sessionID = typeof $script === "object" && $script && $script.sessionID
        ? String($script.sessionID)
        : "unknown";
    const trigger = typeof $trigger === "string" ? $trigger : "unknown";
    const system = typeof $environment === "object" && $environment && $environment.system
        ? String($environment.system)
        : "unknown";

    if (typeof $trigger === "string" && $trigger === "auto-interval") {
        finish(panelTitle, "Automatic refresh is disabled. Run this action manually.", "alert");
        return;
    }

    if (action !== "open" && action !== "close") {
        finish("VPS Knockd", "Configuration error: action must be open or close.", "error");
        return;
    }

    let host;
    let ports;
    let name;

    try {
        host = normalizeHost(args.host);
        ports = parsePorts(args.ports);
        name = String(args.name || "").trim() || host;
    } catch (error) {
        finish(panelTitle, "Configuration error: " + error.message, "error");
        return;
    }

    console.log(
        "[vps-knock] session=" + sessionID +
        " trigger=" + trigger +
        " system=" + system +
        " action=" + action +
        " target=" + host +
        " ports=" + ports.join("|")
    );

    function finishSequence() {
        finish(
            name + " Knock " + actionLabel,
            [
                "Target: " + host,
                "Sequence: " + ports.join(" → "),
                "Mode: serial DIRECT",
                "Please manually verify the actual connectivity status."
            ].join("\n"),
            "good"
        );
    }

    function sendPort(index) {
        if (completed) return;

        const port = ports[index];
        let settled = false;

        function continueSequence(error, response) {
            if (settled || completed) return;
            settled = true;

            const status = response && Number(response.status);
            const result = Number.isFinite(status)
                ? "HTTP " + status
                : (error ? "no HTTP response" : "completed");
            console.log(
                "[vps-knock] session=" + sessionID +
                " completed=" + (index + 1) + "/" + ports.length +
                " port=" + port +
                " result=" + result
            );

            if (index + 1 >= ports.length) {
                finishSequence();
                return;
            }

            setTimeout(function () {
                sendPort(index + 1);
            }, KNOCK_GAP_MILLISECONDS);
        }

        console.log(
            "[vps-knock] session=" + sessionID +
            " sending=" + (index + 1) + "/" + ports.length +
            " port=" + port
        );

        try {
            $httpClient.head({
                url: "http://" + host + ":" + port + "/",
                timeout: KNOCK_REQUEST_TIMEOUT_SECONDS,
                policy: "DIRECT",
                "auto-redirect": false,
                "auto-cookie": false
            }, continueSequence);
        } catch (error) {
            console.log(
                "[vps-knock] session=" + sessionID +
                " failed-to-start port=" + port +
                " error=" + error.message
            );
            continueSequence(error, null);
        }
    }

    sendPort(0);
})();
