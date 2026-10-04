// Surge generic script: sends one knockd port sequence to one VPS.

(function () {
    "use strict";

    // $httpClient has no cancellation handle. Each request is therefore given
    // a unique URL marker and explicitly terminated through Surge's own
    // /v1/requests/kill API before the next knock port is contacted.
    const KNOCK_REQUEST_TIMEOUT_SECONDS = 5;
    const KNOCK_PULSE_MILLISECONDS = 300;
    const ACTIVE_REQUEST_POLL_MILLISECONDS = 50;
    const ACTIVE_REQUEST_MAX_POLLS = 8;
    const ACTIVE_REQUEST_STOP_TIMEOUT_MILLISECONDS = 2000;
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

    function matchingRequestIDs(value, marker) {
        const ids = [];
        const seen = {};

        function visit(node) {
            if (!node || typeof node !== "object") return;

            let serialized;
            try {
                serialized = JSON.stringify(node);
            } catch (error) {
                return;
            }
            if (serialized.indexOf(marker) < 0) return;

            if (Object.prototype.hasOwnProperty.call(node, "id")) {
                const rawID = node.id;
                const id = /^\d+$/.test(String(rawID)) ? Number(rawID) : rawID;
                const key = typeof id + ":" + String(id);
                if (!seen[key]) {
                    seen[key] = true;
                    ids.push(id);
                }
            }

            Object.keys(node).forEach(function (key) {
                visit(node[key]);
            });
        }

        visit(value);
        return ids;
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
                "Mode: serial DIRECT + explicit request termination",
                "Please manually verify the actual connectivity status."
            ].join("\n"),
            "good"
        );
    }

    function sendPort(index) {
        if (completed) return;

        const port = ports[index];
        const marker = "surge-knock-" +
            sessionID.replace(/[^a-zA-Z0-9_-]/g, "_") + "-" +
            Date.now() + "-" + index;
        const requestURL = "http://" + host + ":" + port +
            "/?_surge_knock=" + marker;
        let settled = false;
        let killIssued = false;

        function continueSequence(result) {
            if (settled || completed) return;
            settled = true;

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

        function abortSequence(reason) {
            if (settled || completed) return;
            settled = true;
            console.log(
                "[vps-knock] session=" + sessionID +
                " abort port=" + port +
                " reason=" + reason
            );
            finish(
                name + " Knock " + actionLabel + " Aborted",
                [
                    "Target: " + host,
                    "Sequence stopped at port: " + port,
                    reason,
                    "No later knock ports were contacted."
                ].join("\n"),
                "error"
            );
        }

        function stopActiveRequest(pollNumber) {
            if (settled || completed) return;

            try {
                $httpAPI("GET", "/v1/requests/active", {}, function (activeResult) {
                    if (settled || completed) return;

                    const ids = matchingRequestIDs(activeResult, marker);
                    if (ids.length === 0) {
                        if (killIssued) {
                            continueSequence("explicitly terminated");
                            return;
                        }
                        if (pollNumber + 1 < ACTIVE_REQUEST_MAX_POLLS) {
                            setTimeout(function () {
                                stopActiveRequest(pollNumber + 1);
                            }, ACTIVE_REQUEST_POLL_MILLISECONDS);
                            return;
                        }
                        abortSequence("Unable to locate and terminate the active request safely.");
                        return;
                    }

                    if (killIssued && pollNumber >= ACTIVE_REQUEST_MAX_POLLS) {
                        abortSequence("The request remained active after the termination command.");
                        return;
                    }

                    killIssued = true;
                    let remaining = ids.length;
                    ids.forEach(function (id) {
                        try {
                            $httpAPI("POST", "/v1/requests/kill", {id: id}, function () {
                                if (settled || completed) return;
                                remaining -= 1;
                                if (remaining === 0) {
                                    setTimeout(function () {
                                        stopActiveRequest(pollNumber + 1);
                                    }, ACTIVE_REQUEST_POLL_MILLISECONDS);
                                }
                            });
                        } catch (error) {
                            abortSequence("Failed to terminate request " + id + ": " + error.message);
                        }
                    });
                });
            } catch (error) {
                abortSequence("Failed to inspect active requests: " + error.message);
            }
        }

        console.log(
            "[vps-knock] session=" + sessionID +
            " sending=" + (index + 1) + "/" + ports.length +
            " port=" + port
        );

        try {
            $httpClient.head({
                url: requestURL,
                timeout: KNOCK_REQUEST_TIMEOUT_SECONDS,
                policy: "DIRECT",
                "auto-redirect": false,
                "auto-cookie": false
            }, function (error, response) {
                if (killIssued) return;
                const status = response && Number(response.status);
                const result = Number.isFinite(status)
                    ? "HTTP " + status
                    : (error ? "request ended before explicit termination" : "completed");
                continueSequence(result);
            });

            setTimeout(function () {
                stopActiveRequest(0);
            }, KNOCK_PULSE_MILLISECONDS);
            setTimeout(function () {
                abortSequence("Timed out while terminating the active request.");
            }, ACTIVE_REQUEST_STOP_TIMEOUT_MILLISECONDS);
        } catch (error) {
            console.log(
                "[vps-knock] session=" + sessionID +
                " failed-to-start port=" + port +
                " error=" + error.message
            );
            abortSequence("Failed to start the request: " + error.message);
        }
    }

    sendPort(0);
})();
