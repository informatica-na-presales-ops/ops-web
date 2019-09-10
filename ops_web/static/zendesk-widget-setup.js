zE("webWidget", "updateSettings", {
    webWidget: {
        contactForm: {
            attachments: false,
            title: {
                "*": "Open a ticket"
            }
        },
        launcher: {
            label: {
                "*": "Open a ticket"
            }
        }
    }
});

let email = document.getElementById("signed-in-email").getAttribute("content");

zE("webWidget", "prefill", {
    email: {
        readOnly: true,
        value: email
    }
});
