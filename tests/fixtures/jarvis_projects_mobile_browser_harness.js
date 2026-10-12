/*
 * Pi-browser-only harness for the rendered Core Jarvis UI.
 * Run this file in DevTools on /chat with the viewport set to a phone width
 * (<=760 CSS px). It replaces the exercised /chat/api fetches with in-memory
 * responses, so the proof never creates or edits an owner record.
 */
(async () => {
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const waitFor = async (predicate, label, timeout = 5000) => {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      if (predicate()) return;
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    throw new Error(`Timed out waiting for ${label}.`);
  };
  assert(location.pathname === "/chat" || location.pathname === "/chat/",
    "Open the authenticated Jarvis /chat page before running this harness.");
  assert(matchMedia("(max-width: 760px)").matches,
    "Set the Pi browser viewport to 760 CSS px or narrower before running this harness.");

  const nativeFetch = window.fetch;
  let holdNextProjectRead = true;
  let delayedProjectRead = null;
  let projectCreateCount = 0;
  let projects = [];
  const testChat = {id: "ui-harness-chat", title: "UI harness chat", version: 1};
  const createdProject = {id: "ui-harness-project", title: "Harness project", instructions: "",
    sharedMemory: "", obsidianNoteIds: [], chats: [], version: 1};
  const json = (value) => new Response(JSON.stringify(value), {
    status: 200, headers: {"Content-Type": "application/json"}
  });
  const empty = () => new Response(null, {status: 204});

  window.fetch = async (input, options = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    if (url.origin !== location.origin || !url.pathname.startsWith("/chat/api/")) {
      return nativeFetch(input, options);
    }
    const method = (options.method || (typeof input === "object" && input.method) || "GET").toUpperCase();
    const path = url.pathname;
    if (method === "GET" && path === "/chat/api/projects") {
      if (holdNextProjectRead) {
        holdNextProjectRead = false;
        return new Promise(resolve => { delayedProjectRead = () => resolve(json({projects})); });
      }
      return json({projects});
    }
    if (method === "GET" && path === "/chat/api/projects/trash") return json({projects: []});
    if (method === "GET" && path === "/chat/api/conversations/trash") return json([]);
    if (method === "GET" && path === "/chat/api/conversations") return json({conversations: [testChat]});
    if (method === "GET" && path === "/chat/api/models/conversations") return json({conversations: [testChat]});
    if (method === "GET" && path === "/chat/api/second-brain/notes") return json({notes: []});
    if (method === "GET" && /^\/chat\/api\/conversations\/[^/]+\/messages$/.test(path)) {
      return json({messages: []});
    }
    if (method === "GET" && /^\/chat\/api\/conversations\/[^/]+\/model-settings$/.test(path)) {
      return json({turnSelection: {models: [], availability: "unavailable"}});
    }
    if (method === "POST" && path === "/chat/api/conversations") {
      return json({conversation: testChat});
    }
    if (method === "POST" && path === "/chat/api/projects") {
      projectCreateCount += 1;
      projects = [createdProject];
      return json({project: createdProject});
    }
    if (method === "POST" && /\/project$/.test(path)) return empty();
    throw new Error(`Harness blocked an unexpected API call: ${method} ${path}`);
  };

  const clickView = async (view) => {
    const button = document.querySelector(`.primary-nav [data-view="${view}"]`);
    assert(button && !button.hidden, `The ${view} destination is not available in this build.`);
    button.click();
    await waitFor(() => document.querySelector(`.workspace`)?.dataset.currentView === view,
      `${view} view`);
  };

  try {
    const chatsButton = document.querySelector('.primary-nav [data-view="chat"]');
    await clickView("chat");
    assert(document.getElementById("conversation-panel").dataset.open === "true",
      "Chats must open its conversation drawer on mobile.");
    assert(chatsButton.getAttribute("aria-current") === "page",
      "Chats must remain the selected primary destination while its drawer is open.");

    const manage = document.querySelector(".manage-group");
    const manageSummary = manage.querySelector("summary");
    manageSummary.click();
    await waitFor(() => manage.open && manageSummary.getAttribute("aria-expanded") === "true",
      "Manage opening state");
    const modelsButton = manage.querySelector('[data-view="models-settings"]');
    assert(modelsButton, "The Models destination should be available inside Manage.");
    modelsButton.click();
    await waitFor(() => document.querySelector(".workspace")?.dataset.currentView === "models-settings",
      "Models view");
    await waitFor(() => !manage.open && manageSummary.getAttribute("aria-expanded") === "false",
      "Manage closing after destination selection");
    const modelsPanel = document.querySelector('[data-view-panel="models-settings"]');
    const modelsHeading = modelsPanel.querySelector("h1, h2");
    const headingBounds = modelsHeading.getBoundingClientRect();
    assert(!modelsPanel.hidden && headingBounds.height > 0
      && headingBounds.bottom > 0 && headingBounds.top < window.innerHeight,
    "Choosing a feature from Manage must leave its content visible in the mobile viewport.");
    assert(document.activeElement === modelsHeading,
      "Choosing a feature must move focus to its heading after closing Manage.");

    await clickView("projects");
    await waitFor(() => typeof delayedProjectRead === "function", "the delayed project read");
    const projectRoot = document.querySelector('[data-feature-root="projects"]');
    const projectStatus = projectRoot.querySelector("[data-status]");
    const beforeLateRead = projectStatus.textContent;
    await clickView("chat");
    const afterUnmount = projectStatus.textContent;
    delayedProjectRead();
    await new Promise(resolve => setTimeout(resolve, 50));
    assert(projectStatus.textContent === afterUnmount && afterUnmount === beforeLateRead,
      "A response arriving after Projects unmount must not update its inactive view.");

    await clickView("projects");
    await waitFor(() => projectRoot.querySelector('[data-form]') !== null, "Projects remount");
    await clickView("chat");
    await clickView("projects");
    const form = projectRoot.querySelector("[data-form]");
    form.elements.title.value = "Harness project";
    form.requestSubmit();
    await waitFor(() => projectCreateCount > 0, "the stubbed project create");
    await new Promise(resolve => setTimeout(resolve, 100));
    assert(projectCreateCount === 1,
      `One submit after remount must issue one create; observed ${projectCreateCount}.`);

    await clickView("chat");
    assert(document.getElementById("conversation-panel").dataset.open === "true",
      "Returning to Chats must open the mobile conversation drawer.");
    document.getElementById("new-chat").click();
    await waitFor(() => document.getElementById("conversation-panel").dataset.open !== "true",
      "the existing close-on-new-chat behavior");
    await clickView("chat");
    const conversation = document.querySelector(".conversation-item");
    assert(conversation, "The stubbed chat should be visible in the Chats list.");
    conversation.click();
    await waitFor(() => document.getElementById("conversation-panel").dataset.open !== "true",
      "the existing close-on-chat-selection behavior");

    console.info("PASS: mobile Chats opens one conversation list; Manage closes, updates aria-expanded, and "
      + "focuses the visible Models heading; new chat and selecting a chat close it; "
      + "Projects remount submits one create; late project reads do not update an inactive view.");
  } finally {
    window.fetch = nativeFetch;
  }
})().catch(error => {
  console.error("FAIL: Jarvis mobile/Projects UI harness", error);
  throw error;
});
