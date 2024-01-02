// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package networkmonitor_test

import (
	"context"
	"fmt"
	"testing"

	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfnetworkmonitor "github.com/hashicorp/terraform-provider-aws/internal/service/networkmonitor"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
)

func TestAccNetworkMonitorProbe_basic(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmonitor_probe.test"
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckProbeDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccProbeConfig_basic(rName, "10.0.0.1", 8080, 200),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckProbeExists(ctx, resourceName),
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.destination", "10.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.destination_port", "8080"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.packet_size", "200"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.protocol", "TCP"),
				),
			},
		},
	})
}

func TestAccNetworkMonitorProbe_updates(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmonitor_probe.test"
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckProbeDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccProbeConfig_basic(rName, "10.0.0.1", 8080, 200),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckProbeExists(ctx, resourceName),
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.destination", "10.0.0.1"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.destination_port", "8080"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.packet_size", "200"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.protocol", "TCP"),
				),
			},
			{
				Config: testAccProbeConfig_basic(rName, "10.0.0.2", 8081, 300),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckProbeExists(ctx, resourceName),
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.destination", "10.0.0.2"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.destination_port", "8081"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.packet_size", "300"),
					resource.TestCheckResourceAttr(resourceName, "probe.0.protocol", "TCP"),
				),
			},
		},
	})
}

func TestAccNetworkMonitorProbe_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	resourceName := "aws_networkmonitor_probe.test"
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, "networkMonitor"),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckProbeDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccProbeConfig_basic(rName, "10.0.0.1", 8080, 200),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckMonitorExists(ctx, resourceName),
					acctest.CheckResourceDisappears(ctx, acctest.Provider, tfnetworkmonitor.ResourceMonitor(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckProbeDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).NetworkMonitorConn(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_networkmonitor_probe" {
				continue
			}

			_, err := tfnetworkmonitor.FindProbeByName(ctx, conn, rs.Primary.ID)

			if tfresource.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("Network Monitor Probe %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccCheckProbeExists(ctx context.Context, n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Network Monitor Probe ID is set")
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).NetworkMonitorConn(ctx)

		_, err := tfnetworkmonitor.FindProbeByName(ctx, conn, rs.Primary.ID)

		return err
	}
}

func testAccProbeImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Not found: %s", resourceName)
		}

		return rs.Primary.Attributes["probe_id"], nil
	}
}

func testAccProbeConfig_basic(rName, destination string, port, packetSize int) string {
	return fmt.Sprintf(`
data "aws_region" "current" {}

resource "aws_vpc" "test" {
	cidr_block = "10.0.0.0/16"

	tags = {
	  Name = %[1]q
	}
}
	
resource "aws_subnet" "test" {
	vpc_id            = aws_vpc.test.id
	cidr_block        = cidrsubnet(aws_vpc.test.cidr_block, 8, 0)

	tags = {
	  Name = %[1]q
	}
}

resource "aws_networkmonitor_monitor" "test" {
  aggregation_period = 30
  monitor_name = %[1]q
  tags = {
	Name = %[1]q
  }
}


resource "aws_networkmonitor_probe" "test" {
	monitor_name = aws_networkmonitor_monitor.test.monitor_name
	probe {
		destination = %[2]q
		destination_port = %[3]d
		protocol = "TCP"
		source_arn = aws_subnet.test.arn
		packet_size = %[4]d
	}
}
`, rName, destination, port, packetSize)
}
