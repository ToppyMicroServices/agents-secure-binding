// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package monitoring

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMonitoringDefaultsDoNotExposeAdministrativeAccess(t *testing.T) {
	data, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct {
			Ports       []string `yaml:"ports"`
			Command     []string `yaml:"command"`
			Environment []string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"prometheus", "alertmanager", "grafana"} {
		svc, ok := compose.Services[name]
		if !ok || len(svc.Ports) == 0 {
			t.Fatalf("missing service or port configuration for %s", name)
		}
		for _, port := range svc.Ports {
			if !strings.HasPrefix(port, "127.0.0.1:") {
				t.Errorf("%s publishes a non-loopback port: %s", name, port)
			}
		}
	}
	for _, arg := range compose.Services["prometheus"].Command {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--web.enable-admin-api" || name == "--web.enable-lifecycle" {
			t.Errorf("Prometheus enables an administrative endpoint: %s", arg)
		}
	}
	requiredSecret := false
	for _, value := range compose.Services["grafana"].Environment {
		if strings.HasPrefix(value, "GF_SECURITY_ADMIN_PASSWORD=") {
			secret := strings.TrimPrefix(value, "GF_SECURITY_ADMIN_PASSWORD=")
			requiredSecret = strings.HasPrefix(secret, "${GRAFANA_ADMIN_PASSWORD:?") && strings.HasSuffix(secret, "}")
		}
	}
	if !requiredSecret {
		t.Fatal("Grafana must require a nonempty operator-provided password")
	}
}
