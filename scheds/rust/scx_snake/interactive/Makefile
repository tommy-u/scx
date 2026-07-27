SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

SNAKE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
REPO_ROOT := $(abspath $(SNAKE_DIR)/../../..)
POLICY_DIR := $(SNAKE_DIR)/examples
SNAKE_BIN := $(REPO_ROOT)/target/release/scx_snake
INSPECTOR_MANIFEST := $(REPO_ROOT)/tools/scx_snake_inspector/Cargo.toml
INSPECTOR_BIN := $(REPO_ROOT)/tools/scx_snake_inspector/target/release/scx_snake_inspector

SUDO ?= sudo
POLICY ?= kernel-default-sim
STATS ?= 1
LISTEN ?= 127.0.0.1:8787
WINDOW ?= 10s
MAX_WINDOW ?= 5m
SWITCH_INTERVAL ?= 5

POLICIES := basic kernel-default-sim kernel-default llc llc-random llc-half llc-half-random llc-whole-core llc-whole-core-random previous-only random-idle
SWITCH_TARGETS := $(addprefix switch-,$(POLICIES))

GREEN := \033[0;32m
BOLD_GREEN := \033[1;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
CYAN := \033[0;36m
WHITE := \033[1;37m
NC := \033[0m

.PHONY: help build-snake start stop screensaver build-inspector inspector $(SWITCH_TARGETS)

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
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "start" "Start Snake (POLICY=kernel-default-sim)"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "stop" "Stop Snake gracefully"
	@printf "\n$(BLUE)Policy switches$(NC)\n"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-basic" "Minimal previous-CPU policy"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-kernel-default-sim" "Eight-rung userspace simulation"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-kernel-default" "Kernel default selector"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-llc" "Previous CPU, then previous LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-llc-half" "Previous CPU, then half LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-llc-whole-core" "Whole-core LLC placement"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-previous-only" "Previous CPU only"
	@printf "\n$(BLUE)Demo-only policies$(NC)\n"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-llc-random" "Random idle CPU in previous LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-llc-half-random" "Random idle CPU in previous half LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-llc-whole-core-random" "Random wholly idle core in previous LLC"
	@printf "    $(GREEN)%-31s$(NC) %s\n" "switch-random-idle" "Random allowed idle CPU"
	@printf "\n$(BLUE)Bonus$(NC)\n"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "screensaver" "Cycle every policy until Ctrl-C"
	@printf "\n$(BLUE)Visualization$(NC)\n"
	@printf "  $(YELLOW)*$(NC) $(GREEN)%-31s$(NC) %s\n" "inspector" "Start http://$(LISTEN)"
	@printf "\n$(BLUE)Arguments by target (defaults)$(NC)\n"
	@printf "  $(GREEN)%-18s$(NC) $(YELLOW)%s$(NC)\n" "start" "POLICY=$(POLICY) STATS=$(STATS) SUDO=$(SUDO)"
	@printf "  $(GREEN)%-18s$(NC) $(YELLOW)%s$(NC)\n" "stop" "SUDO=$(SUDO)"
	@printf "  $(GREEN)%-18s$(NC) $(YELLOW)%s$(NC)\n" "switch-*" "SUDO=$(SUDO)"
	@printf "  $(GREEN)%-18s$(NC) $(YELLOW)%s$(NC)\n" "screensaver" "SWITCH_INTERVAL=$(SWITCH_INTERVAL) SUDO=$(SUDO)"
	@printf "  $(GREEN)%-18s$(NC) $(YELLOW)%s$(NC)\n\n" "inspector" "LISTEN=$(LISTEN) WINDOW=$(WINDOW) MAX_WINDOW=$(MAX_WINDOW) SUDO=$(SUDO)"

build-snake:
	cargo build --release -p scx_snake --manifest-path "$(REPO_ROOT)/Cargo.toml"

$(SNAKE_BIN):
	$(MAKE) build-snake

start: build-snake
	@test -f "$(POLICY_DIR)/$(POLICY).toml" || { \
	  echo "unknown policy: $(POLICY)" >&2; \
	  exit 1; \
	}
	$(SUDO) "$(SNAKE_BIN)" --policy "$(POLICY_DIR)/$(POLICY).toml" --stats "$(STATS)"

stop:
	@if $(SUDO) pkill -INT -x scx_snake; then \
	  printf "$(GREEN)Snake stopped$(NC)\n"; \
	else \
	  printf "$(YELLOW)Snake is not running$(NC)\n"; \
	fi

$(SWITCH_TARGETS): switch-%: $(SNAKE_BIN)
	@printf "Activating policy: $(BOLD_GREEN)%s$(NC)\n" "$*"
	@$(SUDO) "$(SNAKE_BIN)" --update-policy "$(POLICY_DIR)/$*.toml"

screensaver: $(SNAKE_BIN)
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

build-inspector:
	cargo build --release --manifest-path "$(INSPECTOR_MANIFEST)"

inspector: build-inspector
	$(SUDO) "$(INSPECTOR_BIN)" --listen "$(LISTEN)" --window "$(WINDOW)" --max-window "$(MAX_WINDOW)"
