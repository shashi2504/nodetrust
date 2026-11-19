package bootpolicy

import (
	"fmt"
	"strings"

	"nodetrust/pkg/eventlog"
)

// Defaults for the Ubuntu 24.04 golden AMI. The partition numbers are those
// of the Ubuntu cloud image (15 = ESP, 16 = /boot); a reviewer confirms them
// against the AMI before the policy is accepted.
var (
	DefaultRequiredCmdline = []string{"ima_policy=tcb", "ima_template=ima-ng", "ima_hash=sha256", "lockdown=integrity"}
	DefaultGrubPartitions  = map[string]string{"(hd0,gpt15)": "/boot/efi", "(hd0,gpt16)": "/boot"}
	DefaultMutableFiles    = []string{"/boot/grub/grubenv"}
	// The firmware boots the removable-media path or the ubuntu entry; both
	// hold the same signed shim, which loads grubx64.efi next to it.
	DefaultEFIChain = EFIChain{
		Shim: []string{"/boot/efi/EFI/BOOT/BOOTX64.EFI", "/boot/efi/EFI/ubuntu/shimx64.efi"},
		Grub: []string{"/boot/efi/EFI/ubuntu/grubx64.efi"},
	}
)

// Reference reads the values a boot policy pins from the event log of a
// trusted boot: one done on a fresh instance of the golden AMI that the probe
// passed. It returns them as an update to base (which may be nil), so a new
// AMI is added next to the ones already there. Nothing here is trusted
// because it is in a log; the output is for review before it is used.
func Reference(base *Policy, l *eventlog.Log, ami, firmwareWhy string) (*Policy, error) {
	p := &Policy{
		RequiredCmdline: DefaultRequiredCmdline,
		GrubPartitions:  DefaultGrubPartitions,
		GrubRoot:        "/boot",
		MutableFiles:    DefaultMutableFiles,
		EFIChain:        DefaultEFIChain,
		SecureBoot:      map[string]string{},
		AMIs:            map[string]AMI{},
	}
	if base != nil {
		c := *base
		p = &c
		p.AMIs = map[string]AMI{}
		for k, v := range base.AMIs {
			p.AMIs[k] = v
		}
	}

	pcr0 := hexs(l.Replay()[0])
	have := false
	for _, v := range p.FirmwarePCR0 {
		have = have || v.SHA256 == pcr0
	}
	if !have {
		p.FirmwarePCR0 = append(p.FirmwarePCR0, Value{SHA256: pcr0, Why: firmwareWhy})
	}

	sb := map[string]string{}
	var a AMI
	for i := range l.Events {
		e := &l.Events[i]
		switch {
		case e.PCR == 7 && (e.Type == eventlog.EvEFIVariableDriverConfig || e.Type == eventlog.EvEFIVariableAuthority):
			v, err := e.ParseVariable()
			if err != nil {
				return nil, fmt.Errorf("event %d: %w", e.Index, err)
			}
			key := v.Name
			if e.Type == eventlog.EvEFIVariableAuthority {
				key = "authority:" + v.Name
			}
			sb[key] = hexs(e.SHA256)
		case e.PCR == 4 && e.Type == eventlog.EvEFIAction:
			p.BootAction = e.String()
		case e.PCR == 5 && e.Type == eventlog.EvEFIGPTEvent:
			a.GPT = hexs(e.SHA256)
		case e.PCR == 8 && e.Type == eventlog.EvIPL && strings.HasPrefix(e.String(), "kernel_cmdline: "):
			a.KernelCmdline = strings.TrimPrefix(e.String(), "kernel_cmdline: ")
		}
	}
	if a.GPT == "" || a.KernelCmdline == "" || len(sb) == 0 {
		return nil, fmt.Errorf("log has no GPT event, kernel command line or Secure Boot variables")
	}
	if base != nil && len(base.SecureBoot) > 0 {
		// Secure Boot keys are the platform's, not the AMI's: a new AMI must
		// not change them silently.
		for k, v := range sb {
			if base.SecureBoot[k] != v {
				return nil, fmt.Errorf("Secure Boot %s differs from the existing policy; review by hand", k)
			}
		}
	} else {
		p.SecureBoot = sb
	}
	p.AMIs[ami] = a
	return p, nil
}
