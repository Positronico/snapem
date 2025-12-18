package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// PromptConfirm asks for y/n confirmation
func (u *UI) PromptConfirm(message string, defaultYes bool) bool {
	var prompt string
	if defaultYes {
		prompt = "[Y/n]"
	} else {
		prompt = "[y/N]"
	}

	if u.useColor {
		fmt.Printf("%s %s ", StyleBold.Render(message), StyleMuted.Render(prompt))
	} else {
		fmt.Printf("%s %s ", message, prompt)
	}

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}

	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return defaultYes
	}

	return input == "y" || input == "yes"
}

// PromptInput asks for text input
func (u *UI) PromptInput(message string) string {
	if u.useColor {
		fmt.Printf("%s ", StyleBold.Render(message))
	} else {
		fmt.Printf("%s ", message)
	}

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	return strings.TrimSpace(input)
}

// PromptUnsecure prompts for "unsecure" bypass
func (u *UI) PromptUnsecure() bool {
	u.Warning("No SOCKET_API_TOKEN set. Malware detection is disabled.")
	u.Info("Get a free API key at https://socket.dev")
	u.Print("")

	if u.useColor {
		fmt.Printf("%s ", StyleWarning.Render("Type 'unsecure' to continue without malware scanning:"))
	} else {
		fmt.Printf("Type 'unsecure' to continue without malware scanning: ")
	}

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	return strings.TrimSpace(strings.ToLower(input)) == "unsecure"
}

// PromptForce prompts for "force" bypass when threats are detected
func (u *UI) PromptForce() bool {
	u.Print("")
	if u.useColor {
		fmt.Printf("%s ", StyleError.Render("Type 'force' to override security blocks (DANGEROUS):"))
	} else {
		fmt.Printf("Type 'force' to override security blocks (DANGEROUS): ")
	}

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	return strings.TrimSpace(strings.ToLower(input)) == "force"
}
