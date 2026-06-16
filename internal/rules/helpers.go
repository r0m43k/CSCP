package rules

import "github.com/r0m43k/CSCP/pkg/rulekit"
//для извлечения контейнеров из Kubernetes
type container struct {
	Name  string
	Raw   map[string]any
}

func containersFromObject(obj rulekit.Object) []container {
	switch obj.Kind {
	case "Pod":
		return containersFromPodSpec(asMap(obj.Raw["spec"]))

	case "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job":
		spec :=  asMap(obj.Raw["spec"])
		template := asMap(spec["template"])
		podSpec := asMap(template["spec"])
		return containersFromPodSpec(podSpec)

	case "CronJob":
		spec := asMap(obj.Raw["spec"])
		jobTemplate := asMap(spec["jobTemplate"])
		jobSpec := asMap(jobTemplate["spec"])
		template := asMap(jobSpec["template"])

		podSpec := asMap(template["spec"])
		return containersFromPodSpec(podSpec)
	

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