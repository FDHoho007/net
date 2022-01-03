const IDM = {
    base_url: "https://idm.myfdweb.de",
    token: {
        refresh_popup: null,
        get: function () {
            let at = localStorage.getItem("access_token");
            if (at == null)
                return null;
            else if (at.split(".")[0] - 30000 < new Date().getTime()) {
                localStorage.removeItem("access_token");
                return null;
            } else
                return at;
        },
        refreshHooks: [],
        refresh: function () {
            return new Promise(function (resolve) {
                if (IDM.refresh_popup == null) {
                    IDM.refresh_popup = window.open(IDM.base_url + "/api/rest/oauth2/auth?response_type=token&state=&redirect_uri=" + IDM_REDIRECT_URI + "&request_credentials=default&client_id=" + IDM_SERVICE_ID + "&scope=" + IDM_SERVICE_ID, "_blank", "width=500,height=700,top=300");
                    const i = setInterval(() => {
                        if (IDM.refresh_popup.location.hash !== "") {
                            let args = {};
                            for (let arg of IDM.refresh_popup.location.hash.substr(1).split("&"))
                                args[arg.split("=")[0]] = decodeURIComponent(arg.split("=")[1]);
                            localStorage.setItem("access_token", args["access_token"]);
                            resolve();
                            IDM.refresh_popup.close();
                            IDM.refresh_popup = null;
                            clearInterval(i);
                            IDM.token.refreshHooks.forEach(hook => hook());
                        }
                    }, 1);
                } else
                    this.refresh_popup.focus();
            });
        },
        delete: function () {
            localStorage.removeItem("access_token");
        }
    },
    api: function (url, method = "GET", body = null, contentType = "application/json", priority = true) {
        return new Promise(function (resolve) {
            let token = IDM.token.get();
            if (token == null) {
                if (!IDM.overlay_visible)
                    IDM.overlay().then(function () {
                        if (priority)
                            IDM.api(url, method, body, contentType, priority).then(r => resolve(r));
                    });
            } else {
                let options = {
                    method: method,
                    headers: {
                        "Authorization": "Bearer " + token
                    },
                };
                if (body != null) {
                    options["body"] = body;
                    options["headers"]["Content-Type"] = contentType;
                }
                fetch(url, options).then(r => r.json().then(j => resolve(j)));
            }
        });
    },
    graphql: function (url, query, variables = {}, priority = true) {
        return IDM.api(url, "POST", JSON.stringify({
            "query": query,
            "variables": variables == null ? [] : variables
        }), "application/json", priority);
    },
    overlay_visible: false,
    overlay: function () {
        return new Promise(function (resolve) {
            let overlay = document.createElement("div");
            overlay.id = "idm-login-overlay";
            overlay.style.position = "fixed";
            overlay.style.top = "0";
            overlay.style.left = "0";
            overlay.style.width = "100%";
            overlay.style.height = "100%";
            overlay.style.zIndex = "10";
            overlay.style.background = "rgba(0,0,0,0.4)";
            let container = document.createElement("div");
            container.style.background = "white";
            container.style.borderRadius = "10px";
            container.style.padding = "20px";
            container.style.textAlign = "center";
            container.style.width = "450px";
            container.style.margin = "15% auto";
            container.style.border = "1px solid gray";
            let h1 = document.createElement("h1");
            h1.innerText = "Anmelden";
            container.appendChild(h1);
            let p = document.createElement("p");
            p.innerText = "Du musst angemeldet sein, um diese Seite aufrufen zu können.";
            container.appendChild(p);
            let button = document.createElement("button");
            button.style.background = "url(hub_logo.png)";
            button.style.height = "75px";
            button.style.width = "75px";
            button.style.border = "none";
            button.style.backgroundSize = "contain";
            button.onclick = function () {
                IDM.token.refresh().then(function () {
                    document.getElementById("idm-login-overlay").remove();
                    IDM.overlay_visible = false;
                    resolve();
                });
            }
            container.appendChild(button);
            overlay.appendChild(container);
            document.body.appendChild(overlay);
            IDM.overlay_visible = true;
        });
    }
};
