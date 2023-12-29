package networkmonitor

import (
	"context"
	"log"
	"time"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go/service/networkmonitor"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_networkmonitor_monitor", name="Monitor")
// @Tags(identifierAttribute="arn")
func ResourceMonitor() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceMonitorCreate,
		ReadWithoutTimeout:   resourceMonitorRead,
		UpdateWithoutTimeout: resourceMonitorUpdate,
		DeleteWithoutTimeout: resourceMonitorDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		CustomizeDiff: verify.SetTagsDiff,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(15 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"aggregation_period": {
				Type:     schema.TypeInt,
				Optional: true,
				ForceNew: true,
			},
			"created_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"modified_at": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"monitor_name": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringMatch(regexache.MustCompile(`^[a-zA-Z0-9_-]+$`), "It can contain only letters, underscores (_), or dashes (-), and can be up to 255 characters"),
			},
			"probes": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"address_family": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"created_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"destination": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringLenBetween(1, 255),
						},
						"destination_port": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(0, 65536),
						},
						"modified_at": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"packet_size": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validation.IntBetween(56, 8500),
						},
						"probe_arn": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"probe_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"probe_tags": {
							Type:     schema.TypeMap,
							Computed: true,
						},
						"protocol": {
							Type:     schema.TypeString,
							Required: true,
						},
						"source_arn": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringMatch(regexache.MustCompile(`^arn:.*$`), "AWS ARN"),
						},
						"state": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"vpc_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
			"state": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
		},
	}
}

func resourceMonitorCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).NetworkMonitorConn(ctx)

	monitor_name := d.Get("monitor_name").(string)

	input := &networkmonitor.CreateMonitorInput{
		MonitorName: aws.String(monitor_name),
		Tags:        getTagsIn(ctx),
	}

	if v, ok := d.GetOk("aggregation_period"); ok {
		input.AggregationPeriod = aws.Int64(int64(v.(int)))
	}

	if v, ok := d.GetOk("probes"); ok && len(v.(*schema.Set).List()) > 0 {
		input.Probes = expandProbes(v.(*schema.Set).List(), getTagsIn(ctx))
	}

	log.Printf("[DEBUG] Creating CloudWatch Network Monitor: %s", input)
	output, err := conn.CreateMonitorWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating CloudWatch Network Monitor: %s", err)
	}

	d.SetId(aws.ToString(output.MonitorName))

	if _, err := waitMonitorCreated(ctx, conn, d.Id(), d.Timeout(schema.TimeoutCreate)); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for Network Monitor Monitor (%s) create: %s", d.Id(), err)
	}

	return append(diags, resourceMonitorRead(ctx, d, meta)...)
}

func resourceMonitorRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).NetworkMonitorConn(ctx)

	n, err := FindMonitorByName(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] CloudWatch Network Monitor Monitor %s not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading CloudWatch Network Monitor Monitor (%s): %s", d.Id(), err)
	}

	d.Set("arn", n.MonitorArn)
	d.Set("aggregation_period", n.AggregationPeriod)
	d.Set("created_at", aws.ToTime(n.CreatedAt).String())
	d.Set("modified_at", aws.ToTime(n.ModifiedAt).String())
	d.Set("monitor_name", n.MonitorName)
	d.Set("probes", flattenProbes(n.Probes))
	d.Set("state", n.State)

	setTagsOut(ctx, n.Tags)

	return diags
}

func resourceMonitorUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).NetworkMonitorConn(ctx)

	if d.HasChangesExcept("tags", "tags_all") {
		input := &networkmonitor.UpdateMonitorInput{
			MonitorName: aws.String(d.Id()),
		}

		if d.HasChange("aggregate_period") {
			if v, ok := d.GetOk("aggregate_period"); ok && v != nil {
				input.AggregationPeriod = aws.Int64(int64(v.(int)))
			}
		}

		_, err := conn.UpdateMonitorWithContext(ctx, input)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating CloudWatch Network Monitor Monitor (%s): %s", d.Id(), err)
		}

		if _, err := waitMonitorUpdated(ctx, conn, d.Id(), d.Timeout(schema.TimeoutUpdate)); err != nil {
			return sdkdiag.AppendErrorf(diags, "waiting for CloudWatch Network Manager VPC Attachment (%s) update: %s", d.Id(), err)
		}
	}

	return append(diags, resourceMonitorRead(ctx, d, meta)...)
}

func resourceMonitorDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).NetworkMonitorConn(ctx)

	log.Printf("[DEBUG] Deleting CloudWatch Network Monitor Probes: %s", d.Id())
	if v, ok := d.GetOk("probes"); ok && len(v.(*schema.Set).List()) > 0 {
		for _, a := range v.(*schema.Set).List() {
			t := a.(map[string]interface{})

			_, err := conn.DeleteProbeWithContext(ctx, &networkmonitor.DeleteProbeInput{
				MonitorName: aws.String(d.Get("monitor_name").(string)),
				ProbeId:     aws.String(t["probe_id"].(string)),
			})

			if err != nil {
				return sdkdiag.AppendErrorf(diags, "deleting CloudWatch Network Monitor Probe (%s): %s", d.Id(), err)
			}

			if _, err := WaitProbeDeleted(ctx, conn, t["probe_id"].(string), d.Id(), d.Timeout(schema.TimeoutDelete)); err != nil {
				return sdkdiag.AppendErrorf(diags, "waiting for CloudWatch Network Monitor Probe (%s) delete: %s", d.Id(), err)
			}
		}
	}

	log.Printf("[DEBUG] Deleting CloudWatch Network Monitor Monitor: %s", d.Id())
	_, err := conn.DeleteMonitorWithContext(ctx, &networkmonitor.DeleteMonitorInput{
		MonitorName: aws.String(d.Id()),
	})

	if tfawserr.ErrCodeEquals(err, networkmonitor.ErrCodeResourceNotFoundException) {
		return nil
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting CloudWatch Network Monitor Monitor (%s): %s", d.Id(), err)
	}

	if _, err := waitMonitorDeleted(ctx, conn, d.Id(), d.Timeout(schema.TimeoutDelete)); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for CloudWatch Network Monitor Monitor (%s) delete: %s", d.Id(), err)
	}

	return diags
}

func expandProbes(o []interface{}, tags map[string]*string) []*networkmonitor.CreateMonitorProbeInput_ {
	if o == nil {
		return nil
	}

	object := make([]*networkmonitor.CreateMonitorProbeInput_, len(o))

	for index, a := range o {
		t := &networkmonitor.CreateMonitorProbeInput_{}
		x := a.(map[string]interface{})

		if v, ok := x["destination"].(string); ok {
			t.Destination = aws.String(v)
		}
		if v, ok := x["destination_port"].(int); ok {
			t.DestinationPort = aws.Int64(int64(v))
		}
		if v, ok := x["packet_size"].(int); ok {
			t.PacketSize = aws.Int64(int64(v))
		}
		if tags != nil {
			t.ProbeTags = tags
		}
		if v, ok := x["protocol"].(string); ok {
			t.Protocol = aws.String(v)
		}
		if v, ok := x["source_arn"].(string); ok {
			t.SourceArn = aws.String(v)
		}

		object[index] = t
	}

	return object
}

func flattenProbes(apiObject []*networkmonitor.Probe) []map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := make([]map[string]interface{}, len(apiObject))

	for index, v := range apiObject {
		t := map[string]interface{}{}

		if x := v.AddressFamily; x != nil {
			t["address_family"] = aws.ToString(x)
		}
		if x := v.Destination; x != nil {
			t["destination"] = aws.ToString(x)
		}
		if x := v.DestinationPort; x != nil {
			t["destination_port"] = aws.ToInt64(x)
		}
		if x := v.PacketSize; x != nil {
			t["packet_size"] = aws.ToInt64(x)
		}
		if x := v.ProbeArn; x != nil {
			t["probe_arn"] = aws.ToString(x)
		}
		if x := v.ProbeId; x != nil {
			t["probe_id"] = aws.ToString(x)
		}
		if x := v.Protocol; x != nil {
			t["protocol"] = aws.ToString(x)
		}
		if x := v.SourceArn; x != nil {
			t["source_arn"] = aws.ToString(x)
		}
		if x := v.State; x != nil {
			t["state"] = aws.ToString(x)
		}
		if x := v.Tags; x != nil {
			t["probe_tags"] = flex.FlattenStringMap(x)
		}
		if x := v.VpcId; x != nil {
			t["vpc_id"] = aws.ToString(x)
		}

		tfMap[index] = t
	}

	return tfMap

}

func FindMonitorByName(ctx context.Context, conn *networkmonitor.NetworkMonitor, monitorName string) (*networkmonitor.GetMonitorOutput, error) {
	input := &networkmonitor.GetMonitorInput{
		MonitorName: aws.String(monitorName),
	}

	output, err := conn.GetMonitorWithContext(ctx, input)

	if tfawserr.ErrCodeEquals(err, networkmonitor.ErrCodeResourceNotFoundException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.Probes == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output, nil
}

func statusMonitorState(ctx context.Context, conn *networkmonitor.NetworkMonitor, monitorName string) retry.StateRefreshFunc {
	return func() (interface{}, string, error) {
		output, err := FindMonitorByName(ctx, conn, monitorName)

		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return output, aws.ToString(output.State), nil
	}
}

func waitMonitorCreated(ctx context.Context, conn *networkmonitor.NetworkMonitor, monitorName string, timeout time.Duration) (*networkmonitor.NetworkMonitor, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{networkmonitor.MonitorStatePending},
		Target:  []string{networkmonitor.MonitorStateActive, networkmonitor.MonitorStateInactive},
		Timeout: timeout,
		Refresh: statusMonitorState(ctx, conn, monitorName),
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*networkmonitor.NetworkMonitor); ok {
		return output, err
	}

	return nil, err
}

func waitMonitorDeleted(ctx context.Context, conn *networkmonitor.NetworkMonitor, monitorName string, timeout time.Duration) (*networkmonitor.NetworkMonitor, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{networkmonitor.MonitorStateDeleting},
		Target:  []string{},
		Timeout: timeout,
		Refresh: statusMonitorState(ctx, conn, monitorName),
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*networkmonitor.NetworkMonitor); ok {
		return output, err
	}

	return nil, err
}

func waitMonitorUpdated(ctx context.Context, conn *networkmonitor.NetworkMonitor, monitorName string, timeout time.Duration) (*networkmonitor.NetworkMonitor, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{networkmonitor.MonitorStatePending},
		Target:  []string{networkmonitor.MonitorStateActive},
		Timeout: timeout,
		Refresh: statusMonitorState(ctx, conn, monitorName),
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*networkmonitor.NetworkMonitor); ok {
		return output, err
	}

	return nil, err
}
