# Root task native observation

`RootTaskNativeObservationRegistry` retains the exact admitted task/source join
before native selection. The root task input coordinator then waits for loader
readiness, selects the enrolled native-input observer, captures and delivers
the prompt context, and binds its typed input receipt to the task before
custody writes stdin. Custody separately records the exact stdin write and EOF;
the later terminal must join both receipts. The task registry joins this
sequence to the current process identity, selected package mount and loader
event, plus the root input observer receipt over the original prompt bytes.

While the process is live, the registry watches the root-owned native bridge
records. A model request is counted only when the actual bridge request handle
has a completed provider response whose retained source receipt closure
contains the task input and every admitted source receipt. Tool results are
counted only when their retained source receipt descends from that exact
provider response and matching selected tool call. Worker stdout and exit
status supply no native request, result, or tool event IDs.

After custody emits its immutable terminal receipt, the registry resolves that
exact retained receipt and returns a separate frozen companion receipt. Both
receipts are required for a successful selected-result capsule. Resolution
fails closed on an expired admission, cancellation or generation change,
authority epoch change, stale source ancestry, missing model response, missing
tool result, process mismatch, replay, or incomplete cleanup. The companion
receipt is an in-process, identity-bound, one-use observation; serializing or
reconstructing its DTO does not recreate issuance authority.

The current protected task recipe schema requires a model response and has no
reviewed no-model override. A safe local model-transport fixture can exercise
this root observation path, but does not establish GLM/account acceptance,
native Hermes acceptance on another host, or target acceptance.
