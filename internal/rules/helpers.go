package rules

import (
	"fmt"
	"strings"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type container struct {
	Name string
	Raw  map[string]any
}

func containersFromObject(obj rulekit.Object) []container {
	return containersFromPodSpec(podSpecFromObject(obj))
}

func podSpecFromObject(obj rulekit.Object) map[string]any {
	switch obj.Kind {
	case "Pod":
		return asMap(obj.Raw["spec"])

	case "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job":
		spec := asMap(obj.Raw["spec"])
		template := asMap(spec["template"])
		return asMap(template["spec"])

	case "CronJob":
		spec := asMap(obj.Raw["spec"])
		jobTemplate := asMap(spec["jobTemplate"])
		jobSpec := asMap(jobTemplate["spec"])
		template := asMap(jobSpec["template"])
		return asMap(template["spec"])

	default:
		return nil
	}
}

func containersFromPodSpec(podSpec map[string]any) []container {
	if podSpec == nil {
		return nil
	}

	rawContainers, ok := podSpec["containers"].([]any)
	if !ok {
		return nil
	}

	containers := make([]container, 0, len(rawContainers))

	for _, rawContainer := range rawContainers {
		containerMap := asMap(rawContainer)
		if containerMap == nil {
			continue
		}

		name, _ := containerMap["name"].(string)
		containers = append(containers, container{
			Name: name,
			Raw:  containerMap,
		})
	}

	return containers
}

func asMap(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func asString(value any) string {
	result, _ := value.(string)
	return result
}

func boolValue(value any) (bool, bool) {
	result, ok := value.(bool)
	return result, ok
}

func int64Value(value any) (int64, bool) {
	switch result := value.(type) {
	case int:
		return int64(result), true
	case int8:
		return int64(result), true
	case int16:
		return int64(result), true
	case int32:
		return int64(result), true
	case int64:
		return result, true
	case uint:
		return int64(result), true
	case uint8:
		return int64(result), true
	case uint16:
		return int64(result), true
	case uint32:
		return int64(result), true
	case uint64:
		if result > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(result), true
	case float64:
		if result != float64(int64(result)) {
			return 0, false
		}
		return int64(result), true
	default:
		return 0, false
	}
}

func stringSliceFromAny(value any) []string {
	rawItems, ok := value.([]any)
	if !ok {
		return nil
	}

	items := make([]string, 0, len(rawItems))
	for _, rawItem := range rawItems {
		item, ok := rawItem.(string)
		if !ok {
			continue
		}

		items = append(items, item)
	}

	return items
}

func containsDangerousCapability(capabilities []string) []string {
	dangerous := map[string]struct{}{
		"SYS_ADMIN":  {},
		"NET_ADMIN":  {},
		"SYS_PTRACE": {},
	}

	matches := []string{}
	for _, capability := range capabilities {
		normalized := strings.ToUpper(capability)
		if _, ok := dangerous[normalized]; ok {
			matches = append(matches, normalized)
		}
	}

	return matches
}

func newFinding(rule rulekit.Rule, obj rulekit.Object, evidence map[string]any) rulekit.Finding {
	metadata := rule.Metadata()

	return rulekit.Finding{
		RuleID:      metadata.ID,
		Resource:    obj,
		Severity:    metadata.Severity,
		Title:       metadata.Title,
		Description: metadata.Description,
		Evidence:    evidence,
		Remediation: metadata.Remediation,
	}
}

func containerEvidence(container container, key string, value any) map[string]any {
	return map[string]any{
		"containerName": container.Name,
		key:             value,
	}
}

func missingResourceLimits(container container) []string {
	resources := asMap(container.Raw["resources"])
	limits := asMap(resources["limits"])
	missing := []string{}

	if _, ok := limits["cpu"]; !ok {
		missing = append(missing, "cpu")
	}

	if _, ok := limits["memory"]; !ok {
		missing = append(missing, "memory")
	}

	return missing
}

func latestTagEvidence(image string) (map[string]any, bool) {
	if image == "" {
		return nil, false
	}

	imageWithoutDigest := strings.Split(image, "@")[0]
	lastSlash := strings.LastIndex(imageWithoutDigest, "/")
	lastColon := strings.LastIndex(imageWithoutDigest, ":")

	if lastColon <= lastSlash {
		return map[string]any{
			"image":  image,
			"tag":    "latest",
			"reason": "image tag is omitted and defaults to latest",
		}, true
	}

	tag := imageWithoutDigest[lastColon+1:]
	if strings.EqualFold(tag, "latest") {
		return map[string]any{
			"image": image,
			"tag":   tag,
		}, true
	}

	return nil, false
}

func rootReason(containerSecurityContext, podSecurityContext map[string]any) (string, bool) {
	if runAsUser, ok := int64Value(containerSecurityContext["runAsUser"]); ok {
		if runAsUser == 0 {
			return "container securityContext.runAsUser is 0", true
		}
		return "", false
	}

	if runAsUser, ok := int64Value(podSecurityContext["runAsUser"]); ok {
		if runAsUser == 0 {
			return "pod securityContext.runAsUser is 0", true
		}
		return "", false
	}

	if runAsNonRoot, ok := boolValue(containerSecurityContext["runAsNonRoot"]); ok && runAsNonRoot {
		return "", false
	}

	if runAsNonRoot, ok := boolValue(podSecurityContext["runAsNonRoot"]); ok && runAsNonRoot {
		return "", false
	}

	return "runAsUser and runAsNonRoot are not set", true
}

func namespacedName(obj rulekit.Object) string {
	if obj.Namespace == "" {
		return obj.Name
	}

	return fmt.Sprintf("%s/%s", obj.Namespace, obj.Name)
}
