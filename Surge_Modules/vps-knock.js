// Surge generic script: sends one knockd port sequence to one VPS.

(function () {
    "use strict";

    const KNOCK_REQUEST_TIMEOUT_SECONDS = 1;
    const KNOCK_GAP_MILLISECONDS = 100;
    const FINISH_GRACE_MILLISECONDS = 250;
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

    ports.forEach(function (port, index) {
        setTimeout(function () {
            console.log(
                "[vps-knock] " + name + " " + actionLabel +
                " " + (index + 1) + "/" + ports.length + ": " + port
            );

            try {
                $httpClient.head({
                    url: "http://" + host + ":" + port + "/",
                    timeout: KNOCK_REQUEST_TIMEOUT_SECONDS,
                    policy: "DIRECT",
                    "auto-redirect": false,
                    "auto-cookie": false
                }, function () {});
            } catch (error) {
                console.log("[vps-knock] Failed to start the request for port " + port + ": " + error.message);
            }
        }, index * KNOCK_GAP_MILLISECONDS);
    });

    setTimeout(function () {
        finish(
            name + " Knock " + actionLabel,
            [
                "Target: " + host,
                "Sequence: " + ports.join(" → "),
                "Please manually verify the actual connectivity status."
            ].join("\n"),
            "good"
        );
    }, (ports.length - 1) * KNOCK_GAP_MILLISECONDS + FINISH_GRACE_MILLISECONDS);
})();
