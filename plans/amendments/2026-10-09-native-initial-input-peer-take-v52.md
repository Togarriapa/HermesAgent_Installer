# Native initial input peer take v52

Repairs original HI08/HI11/RB-T08 startup delivery: actual producer takes rootselected source handle via fixed no-selector endpoint after loader readiness and before stdin. Root coordinator never declares queued input delivered; no receiptID in prompt/env/argv or pendingpair prerequisite. All scope/baseline/acceptance unchanged.
