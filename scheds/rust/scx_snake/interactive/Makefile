SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

SNAKE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
REPO_ROOT := $(abspath $(SNAKE_DIR)/../../..)
POLICY_DIR := $(SNAKE_DIR)/examples
SNAKE_BIN := $(REPO_ROOT)/target/release/scx_snake
CELL_GALLERY_BIN := $(REPO_ROOT)/target/release/scx_snake_cell_gallery
CELL_GALLERY_MANIFEST := $(SNAKE_DIR)/demos/cell_gallery/Cargo.toml
INSPECTOR_MANIFEST := $(REPO_ROOT)/tools/scx_snake_inspector/Cargo.toml
INSPECTOR_BIN := $(REPO_ROOT)/tools/scx_snake_inspector/target/release/scx_snake_inspector

SUDO ?= sudo
POLICY ?= kernel-default-sim
STATS ?= 1
FAIRNESS ?= fifo
FAIRNESS_CPU ?=
FAIRNESS_DURATION ?= 20
LISTEN ?= 127.0.0.1:8787
WINDOW ?= 10s
MAX_WINDOW ?= 5m
SWITCH_INTERVAL ?= 5
CELL ?= 1
DEMO_INTERVAL ?= 2
ART_INTERVAL ?= 10
ART_CYCLES ?= 0
RESTORE_POLICY ?= kernel-default-sim
CELL_DEMO := $(SNAKE_DIR)/interactive/cell-demo.sh
FAIRNESS_DEMO := $(SNAKE_DIR)/interactive/fairness-demo.sh

POLICIES := basic kernel-default-sim kernel-default llc llc-random llc-half llc-half-random llc-whole-core llc-whole-core-random previous-only random-idle

GREEN := \033[0;32m
BOLD_GREEN := \033[1;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
CYAN := \033[0;36m
WHITE := \033[1;37m
NC := \033[0m

.PHONY: help start stop screensaver build-inspector inspector build-cell-gallery cell-demo cell-demo-start cell-demo-move cell-demo-status cell-demo-stop cell-art-gallery fairness-demo $(POLICIES)

help:
	@printf "\n"
	@printf "                $(CYAN)+-------------------------------+$(NC)\n"
	@printf "                $(CYAN)|$(WHITE)%-31s$(CYAN)|$(NC)\n" "           scx_snake"
	@printf "                $(CYAN)|$(GREEN)%-21s$(YELLOW)%-4s$(CYAN)%-6s|$(NC)\n" '      ______' '|--|' ''
	@printf "                $(CYAN)|$(GREEN)%-21s$(YELLOW)%-4s$(CYAN)%-6s|$(NC)\n" '    /  o   \__>~' '|  |' ''
	@printf "                $(CYAN)|$(GREEN)%-21s$(YELLOW)%-4s$(CYAN)%-6s|$(NC)\n" "   /           \\" '|--|' ''
	@printf "                $(CYAN)|$(GREEN)%-21s$(YELLOW)%-4s$(CYAN)%-6s|$(NC)\n" '   \           /' '|  |' ''
	@printf "                $(CYAN)|$(GREEN)%-21s$(YELLOW)%-4s$(CYAN)%-6s|$(NC)\n" "    \_____     \\" '|--|' ''
	@printf "                $(CYAN)|$(GREEN)%-21s$(YELLOW)%-4s$(CYAN)%-6s|$(NC)\n" "          \     \\" '|  |' ''
	@printf "                $(CYAN)|$(GREEN)%-21s$(YELLOW)%-4s$(CYAN)%-6s|$(NC)\n" '    ______/     /' '|--|' ''
	@printf "                $(CYAN)|$(GREEN)%-21s$(YELLOW)%-4s$(CYAN)%-6s|$(NC)\n" '   /___________/' '|  |' ''
	@printf "                $(CYAN)+-------------------------------+$(NC)\n"
	@printf "              $(WHITE)declarative sched_ext policy playground$(NC)\n\n"
	@printf "$(BLUE)Scheduler$(NC)\n"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "start" "Start Snake"
	@printf "%36s$(YELLOW)%s$(NC)\n" "" "POLICY=$(POLICY) FAIRNESS=$(FAIRNESS) STATS=$(STATS)"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "stop" "Stop Snake gracefully"
	@printf "\n$(BLUE)Policy switches$(NC)\n"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "basic" "Minimal previous-CPU policy"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "kernel-default-sim" "Eight-rung userspace simulation"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "kernel-default" "Kernel default selector"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "llc" "Previous CPU, then previous LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "llc-half" "Previous CPU, then half LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "llc-whole-core" "Whole-core LLC placement"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "previous-only" "Previous CPU only"
	@printf "\n$(BLUE)Demo-only policies$(NC)\n"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "llc-random" "Random idle CPU in previous LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "llc-half-random" "Random idle CPU in previous half LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "llc-whole-core-random" "Random wholly idle core in previous LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "random-idle" "Random allowed idle CPU"
	@printf "\n$(BLUE)Bonus$(NC)\n"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "screensaver" "Cycle every policy until Ctrl-C"
	@printf "%36s$(YELLOW)%s$(NC)\n" "" "SWITCH_INTERVAL=$(SWITCH_INTERVAL)"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "cell-demo" "Move two bursty tasks through cells 0, 1, and overlapping cell 2"
	@printf "%36s$(YELLOW)%s$(NC)\n" "" "DEMO_INTERVAL=$(DEMO_INTERVAL)"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "cell-art-gallery" "Cycle flower, heart, cat, and snake migration art"
	@printf "%36s$(YELLOW)%s$(NC)\n" "" "ART_INTERVAL=$(ART_INTERVAL) ART_CYCLES=$(ART_CYCLES) RESTORE_POLICY=$(RESTORE_POLICY)"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "fairness-demo" "Validate VTIME or EEVDF shares with pinned CPU-bound tasks"
	@printf "%36s$(YELLOW)%s$(NC)\n" "" "FAIRNESS_CPU=$(FAIRNESS_CPU) FAIRNESS_DURATION=$(FAIRNESS_DURATION)"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "cell-demo-start" "Start tasks in generated cell 0"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "cell-demo-move" "Move tasks to CELL=0, 1, or 2"
	@printf "%36s$(YELLOW)%s$(NC)\n" "" "CELL=$(CELL)"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "cell-demo-status" "Show each task's current CPU"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "cell-demo-stop" "Stop cell demo tasks"
	@printf "\n$(BLUE)Visualization$(NC)\n"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "inspector" "Start http://$(LISTEN)"
	@printf "%36s$(YELLOW)%s$(NC)\n\n" "" "LISTEN=$(LISTEN) WINDOW=$(WINDOW) MAX_WINDOW=$(MAX_WINDOW)"

start:
	@test -f "$(POLICY_DIR)/$(POLICY).toml" || { \
	  echo "unknown policy: $(POLICY)" >&2; \
	  exit 1; \
	}
	$(SUDO) "$(SNAKE_BIN)" --policy "$(POLICY_DIR)/$(POLICY).toml" --fairness "$(FAIRNESS)" --stats "$(STATS)"

stop:
	@if $(SUDO) pkill -INT -x scx_snake; then \
	  printf "$(GREEN)Snake stopped$(NC)\n"; \
	else \
	  printf "$(YELLOW)Snake is not running$(NC)\n"; \
	fi

$(POLICIES): %:
	@printf "Activating policy: $(BOLD_GREEN)%s$(NC)\n" "$*"
	@$(SUDO) "$(SNAKE_BIN)" --update-policy "$(POLICY_DIR)/$*.toml"

screensaver:
	@trap 'printf "\n$(YELLOW)Screensaver stopped$(NC)\n"; exit 0' INT TERM; \
	while true; do \
	  for policy in $(POLICIES); do \
	    printf "$(BOLD_GREEN)Current policy: %s$(NC)\n" "$$policy"; \
	    if ! $(SUDO) "$(SNAKE_BIN)" --update-policy "$(POLICY_DIR)/$$policy.toml" >/dev/null; then \
	      exit 1; \
	    fi; \
	    sleep "$(SWITCH_INTERVAL)"; \
	  done; \
	done

cell-demo:
	@SNAKE_BIN="$(SNAKE_BIN)" SUDO="$(SUDO)" DEMO_INTERVAL="$(DEMO_INTERVAL)" "$(CELL_DEMO)" demo

cell-demo-start:
	@SNAKE_BIN="$(SNAKE_BIN)" SUDO="$(SUDO)" "$(CELL_DEMO)" start

cell-demo-move:
	@SNAKE_BIN="$(SNAKE_BIN)" SUDO="$(SUDO)" CELL="$(CELL)" "$(CELL_DEMO)" move

cell-demo-status:
	@SNAKE_BIN="$(SNAKE_BIN)" SUDO="$(SUDO)" "$(CELL_DEMO)" status

cell-demo-stop:
	@SNAKE_BIN="$(SNAKE_BIN)" SUDO="$(SUDO)" "$(CELL_DEMO)" stop

fairness-demo:
	@FAIRNESS_CPU="$(FAIRNESS_CPU)" FAIRNESS_DURATION="$(FAIRNESS_DURATION)" "$(FAIRNESS_DEMO)"

build-cell-gallery:
	cargo build --release --manifest-path "$(CELL_GALLERY_MANIFEST)"

cell-art-gallery: build-cell-gallery
	@test -f "$(POLICY_DIR)/$(RESTORE_POLICY).toml" || { \
	  echo "unknown restore policy: $(RESTORE_POLICY)" >&2; \
	  exit 1; \
	}
	@$(SUDO) "$(CELL_GALLERY_BIN)" \
	  --interval "$(ART_INTERVAL)" \
	  --cycles "$(ART_CYCLES)" \
	  --restore-policy "$(POLICY_DIR)/$(RESTORE_POLICY).toml"

build-inspector:
	cargo build --release --manifest-path "$(INSPECTOR_MANIFEST)"

inspector: build-inspector
	$(SUDO) "$(INSPECTOR_BIN)" --listen "$(LISTEN)" --window "$(WINDOW)" --max-window "$(MAX_WINDOW)"
