/*
 * Pi-browser-only harness for the rendered Core Jarvis UI.
 * Run this file in DevTools on /chat with the viewport set to a phone width
 * (<=760 CSS px). It replaces the exercised /chat/api fetches with in-memory
 * responses, so the proof never creates or edits an owner record.
 */
(async () => {
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  const waitForResult = async (predicate, timeout = 1500) => {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      if (predicate()) return true;
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    return Boolean(predicate());
  };
  assert(location.pathname === "/chat" || location.pathname === "/chat/",
    "Open the authenticated Jarvis /chat page before running this harness.");
  assert(matchMedia("(max-width: 760px)").matches,
    "Set the Pi browser viewport to 760 CSS px or narrower before running this harness.");

  const nativeFetch = window.fetch;
  let holdNextProjectRead = true;
  let delayedProjectRead = null;
  let delayedProjectSignal = null;
  let projectCreateCount = 0;
  let projects = [];
  const testChat = {id: "ui-harness-chat", title: "UI harness chat", version: 1};
  const createdProject = {id: "ui-harness-project", title: "Harness project", instructions: "",
    sharedMemory: "", obsidianNoteIds: [], chats: [], version: 1};
  const staleProject = {id: "ui-harness-stale-project", title: "Late inactive project", instructions: "",
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
        delayedProjectSignal = options.signal || (typeof input === "object" ? input.signal : null) || null;
        return new Promise(resolve => { delayedProjectRead = () => resolve(json({projects: [staleProject]})); });
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
    if (!button || button.hidden) return false;
    button.click();
    return waitForResult(() => document.querySelector(`.workspace`)?.dataset.currentView === view);
  };

  const withinViewport = (element) => {
    if (!element || element.hidden || !element.getClientRects().length) return false;
    const style = getComputedStyle(element), rect = element.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0
      && rect.right > 0 && rect.bottom > 0 && rect.left < innerWidth && rect.top < innerHeight;
  };
  const chatSurface = () => {
    const main = document.getElementById("main-content");
    const modelControls = document.getElementById("turn-model-controls");
    const input = document.getElementById("message-input");
    const send = document.getElementById("send-button");
    const panel = document.getElementById("conversation-panel");
    const toggle = document.getElementById("history-toggle");
    return {
      view: document.querySelector(".workspace")?.dataset.currentView || null,
      selected: document.querySelector('.primary-nav [data-view="chat"]')?.getAttribute("aria-current") || null,
      mainVisible: withinViewport(main),
      modelControlsVisible: withinViewport(modelControls),
      messageInputVisible: withinViewport(input),
      sendVisible: withinViewport(send),
      drawerOpen: panel?.dataset.open === "true",
      drawerVisible: withinViewport(panel),
      historyExpanded: toggle?.getAttribute("aria-expanded") || null,
      historyLabel: toggle?.getAttribute("aria-label") || null,
      messageInputFocusable: Boolean(input && !input.disabled && input.tabIndex >= 0)
    };
  };

  try {
    const chatsButton = document.querySelector('.primary-nav [data-view="chat"]');
    const chatsOpened = await clickView("chat");
    const initialDrawer = document.getElementById("conversation-panel");
    const selectedChatNavigationRetained = Boolean(chatsOpened && chatsButton?.getAttribute("aria-current") === "page");
    const initialChatSurface = chatSurface();
    const chatNavigationShowsThreadComposer = Boolean(chatsOpened && selectedChatNavigationRetained
      && initialChatSurface.view === "chat" && initialChatSurface.mainVisible
      && initialChatSurface.modelControlsVisible && initialChatSurface.messageInputVisible
      && initialChatSurface.sendVisible && initialChatSurface.messageInputFocusable
      && !initialChatSurface.drawerOpen && initialChatSurface.historyExpanded === "false"
      && initialChatSurface.historyLabel === "Show conversations");
    const historyToggle = document.getElementById("history-toggle");
    if (historyToggle && initialDrawer?.dataset.open !== "true") historyToggle.click();
    const historyDrawerOpensFromControl = Boolean(await waitForResult(() =>
      initialDrawer?.dataset.open === "true" && historyToggle?.getAttribute("aria-expanded") === "true"
      && historyToggle?.getAttribute("aria-label") === "Return to conversation"));
    const conversation = document.querySelector(".conversation-item");
    if (historyDrawerOpensFromControl && conversation) conversation.click();
    const selectionReturnsToUsableComposer = Boolean(conversation && await waitForResult(() => {
      const surface = chatSurface();
      const selectedConversation = document.querySelector('.conversation-item[aria-current="page"]');
      return !surface.drawerOpen && surface.view === "chat" && surface.mainVisible
        && surface.modelControlsVisible && surface.messageInputVisible && surface.sendVisible
        && Boolean(selectedConversation);
    }));
    const selectionClosesDrawer = Boolean(selectionReturnsToUsableComposer
      && initialDrawer?.dataset.open !== "true"
      && historyToggle?.getAttribute("aria-expanded") === "false"
      && historyToggle?.getAttribute("aria-label") === "Show conversations");
    const inputAfterSelection = document.getElementById("message-input");
    inputAfterSelection?.focus({preventScroll: true});
    const selectedChatComposerAcceptsFocus = Boolean(selectionClosesDrawer
      && document.activeElement === inputAfterSelection);

    const manageGroups = [...document.querySelectorAll('.primary-nav .nav-group[data-nav-group="manage"]')];
    const manage = manageGroups.length === 1 ? manageGroups[0] : null;
    const manageSummary = manage?.querySelector(':scope > summary');
    const systemSections = [...manage?.querySelectorAll('[aria-labelledby="manage-system-heading"]') || []];
    const systemSection = systemSections.length === 1 ? systemSections[0] : null;
    const systemHeading = systemSection?.querySelector('#manage-system-heading');
    const systemHeadingAndSectionUnique = Boolean(manage && systemSections.length === 1
      && systemHeading?.textContent.trim() === "System");
    const modelsButtons = [...systemSection?.querySelectorAll('[data-view="models-settings"]') || []];
    const modelsButtonUniqueInsideSystem = modelsButtons.length === 1
      && modelsButtons[0].closest('[aria-labelledby="manage-system-heading"]') === systemSection;
    const modelsButton = modelsButtonUniqueInsideSystem ? modelsButtons[0] : null;
    if (manage && manageSummary && !manage.open) manageSummary.click();
    const systemOpens = Boolean(manage && manageSummary && systemHeadingAndSectionUnique
      && modelsButtonUniqueInsideSystem && await waitForResult(() => manage.open
        && manageSummary.getAttribute("aria-expanded") === "true"));
    if (systemOpens && modelsButton) modelsButton.click();
    const modelsSelected = Boolean(systemOpens && modelsButton
      && await waitForResult(() => document.querySelector(".workspace")?.dataset.currentView === "models-settings"));
    const systemClosed = Boolean(modelsSelected
      && await waitForResult(() => !manage.open && manageSummary.getAttribute("aria-expanded") === "false"));
    const modelsHeadingVisible = await waitForResult(() => {
      const panel = document.querySelector('[data-view-panel="models-settings"]');
      const heading = panel?.querySelector("h1, h2");
      if (!modelsSelected || !panel || panel.hidden || !heading || !heading.getClientRects().length) return false;
      const bounds = heading.getBoundingClientRect();
      return bounds.width > 0 && bounds.height > 0 && bounds.bottom > 0 && bounds.top < innerHeight;
    });
    const modelsHeadingFocused = await waitForResult(() => {
      const heading = document.querySelector('[data-view-panel="models-settings"] h1, [data-view-panel="models-settings"] h2');
      return Boolean(modelsSelected && heading && document.activeElement === heading);
    });

    let lateProjectObservation = null;
    let inactiveProjectViewUnaffectedByLateRead = false;
    let projectCreateFormReached = false;
    if (await clickView("projects")) {
      const requestStarted = await waitForResult(() => typeof delayedProjectRead === "function");
      const projectRoot = document.querySelector('[data-feature-root="projects"]');
      const projectStatus = projectRoot?.querySelector("[data-status]");
      const projectList = projectRoot?.querySelector("[data-project-list]");
      if (requestStarted && projectStatus && projectList && await clickView("chat")) {
        const beforeLateRead = projectStatus.textContent;
        const projectListBeforeLateRead = projectList.textContent;
        const afterUnmount = projectStatus.textContent;
        const projectListAfterUnmount = projectList.textContent;
        delayedProjectRead();
        await new Promise(resolve => setTimeout(resolve, 50));
        lateProjectObservation = {
          scopeAborted: delayedProjectSignal?.aborted === true,
          statusBeforeUnmount: beforeLateRead,
          statusAfterUnmount: afterUnmount,
          statusAfterLateResponse: projectStatus.textContent,
          projectListBeforeUnmount: projectListBeforeLateRead,
          projectListAfterUnmount,
          projectListAfterLateResponse: projectList.textContent
        };
        inactiveProjectViewUnaffectedByLateRead = Boolean(lateProjectObservation.scopeAborted
          && lateProjectObservation.statusAfterLateResponse === lateProjectObservation.statusAfterUnmount
          && lateProjectObservation.statusAfterUnmount === lateProjectObservation.statusBeforeUnmount
          && lateProjectObservation.projectListAfterLateResponse === lateProjectObservation.projectListAfterUnmount
          && lateProjectObservation.projectListAfterUnmount === lateProjectObservation.projectListBeforeUnmount);
      }
      if (await clickView("projects")) {
        projectCreateFormReached = await waitForResult(
          () => Boolean(projectRoot?.querySelector("[data-form]")));
        if (projectCreateFormReached && await clickView("chat") && await clickView("projects")) {
          const form = projectRoot?.querySelector("[data-form]");
          if (form) {
            form.elements.title.value = "Harness project";
            form.requestSubmit();
            await waitForResult(() => projectCreateCount > 0);
            await new Promise(resolve => setTimeout(resolve, 100));
          }
        }
      }
    }

    const projectCreateRequests = projectCreateCount;
    const chatReachedForDrawer = await clickView("chat");
    const chatSurfaceBeforeHistory = chatSurface();
    const returningToChatShowsComposer = Boolean(chatReachedForDrawer && chatSurfaceBeforeHistory.mainVisible
      && chatSurfaceBeforeHistory.modelControlsVisible && chatSurfaceBeforeHistory.messageInputVisible
      && !chatSurfaceBeforeHistory.drawerOpen);
    if (chatsButton && chatSurfaceBeforeHistory.view === "chat") chatsButton.click();
    const repeatedChatsOpensDrawer = Boolean(await waitForResult(
      () => initialDrawer?.dataset.open === "true" && historyToggle?.getAttribute("aria-expanded") === "true"));
    const newChat = document.getElementById("new-chat");
    if (newChat && initialDrawer?.dataset.open === "true") newChat.click();
    const newChatClosesDrawerAndFocusesComposer = Boolean(await waitForResult(() => {
      const surface = chatSurface();
      return !surface.drawerOpen && surface.mainVisible && surface.modelControlsVisible
        && surface.messageInputVisible && document.activeElement === document.getElementById("message-input");
    }));

    const checks = {
      chatNavigationShowsThreadComposer,
      selectedChatNavigationRetained,
      historyDrawerOpensFromControl,
      selectionReturnsToUsableComposer,
      selectionClosesDrawer,
      selectedChatComposerAcceptsFocus,
      systemHeadingAndSectionUnique,
      modelsButtonUniqueInsideSystem,
      modelsCanBeSelectedFromSystem: systemOpens && modelsSelected,
      systemClosesAfterModelsSelection: systemClosed,
      modelsHeadingVisibleAfterMenuCloses: modelsHeadingVisible,
      focusMovesToVisibleModelsHeading: modelsHeadingFocused,
      projectCreateFormReached,
      projectsScopeAbortedBeforeLateResponse: lateProjectObservation?.scopeAborted === true,
      inactiveProjectStatusAndListUnaffectedByLateRead: inactiveProjectViewUnaffectedByLateRead,
      oneCreateForOneSubmit: projectCreateRequests === 1,
      returningToChatShowsComposer,
      repeatedChatsOpensDrawer,
      newChatClosesDrawerAndFocusesComposer
    };
    const failures = Object.entries(checks).filter(([, passed]) => passed !== true).map(([name]) => name);
    return {
      result: failures.length ? "fail" : "pass",
      viewport: {width: innerWidth, height: innerHeight},
      checks,
      failures,
      observations: {firstChatSurface: initialChatSurface, selectedChatSurface: chatSurface(),
        lateProjectResponse: lateProjectObservation, remountedProjectCreateRequests: projectCreateRequests},
      scope: "in-memory fetch stubs only; POST request objects are intercepted before network transmission"
    };
  } finally {
    window.fetch = nativeFetch;
  }
})().catch(error => {
  console.error("FAIL: Jarvis mobile/Projects UI harness", error);
  throw error;
});
