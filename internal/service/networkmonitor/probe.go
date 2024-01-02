package networkmonitor

import (
	"context"
	"fmt"
	"log"
	"strings"
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

// @SDKResource("aws_networkmonitor_probe", name="Probe")
// @Tags(identifierAttribute="arn")
func ResourceProbe() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceProbeCreate,
		ReadWithoutTimeout:   resourceProbeRead,
		UpdateWithoutTimeout: resourceProbeUpdate,
		DeleteWithoutTimeout: resourceProbeDelete,

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
			"monitor_name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"probe": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
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
						"tags": {
							Type:     schema.TypeMap,
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

func resourceProbeCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).NetworkMonitorConn(ctx)

	monitorName := d.Get("monitor_name").(string)
	probe := expandProbe(d.Get("probe").([]interface{})[0].(map[string]interface{}), getTagsIn(ctx))

	input := &networkmonitor.CreateProbeInput{
		MonitorName: aws.String(monitorName),
		Probe:       probe,
		Tags:        getTagsIn(ctx),
	}

	log.Printf("[DEBUG] Creating CloudWatch Network Monitor Probe: %s", input)
	output, err := conn.CreateProbeWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating CloudWatch Network Monitor Probe: %s", err)
	}

	//d.SetId(aws.ToString(output.ProbeId))
	d.SetId(fmt.Sprintf("%s:%s", aws.ToString(output.ProbeId), monitorName))
	d.Set("monitor_name", monitorName)

	if _, err := waitProbeCreated(ctx, conn, d.Id(), d.Timeout(schema.TimeoutCreate)); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for Network Monitor Probe (%s) create: %s", d.Id(), err)
	}

	return append(diags, resourceProbeRead(ctx, d, meta)...)
}

func resourceProbeRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).NetworkMonitorConn(ctx)

	n, err := FindProbeByName(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN]CloudWatch Network Monitor Probe %s not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading CloudWatch Network Monitor Probe (%s): %s", d.Id(), err)
	}

	d.Set("arn", n.ProbeArn)
	d.Set("probe", flattenProbe(n))
	d.Set("state", n.State)

	setTagsOut(ctx, n.Tags)

	return diags
}

func resourceProbeUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).NetworkMonitorConn(ctx)

	if d.HasChangesExcept("tags", "tags_all") {
		input := &networkmonitor.UpdateProbeInput{
			MonitorName: aws.String(d.Get("monitor_name").(string)),
			ProbeId:     aws.String(d.Id()),
		}

		if d.HasChange("probe") {
			probe := expandProbe(d.Get("probe").([]interface{})[0].(map[string]interface{}), getTagsIn(ctx))
			if probe.Destination != nil {
				input.Destination = probe.Destination
			}
			if probe.DestinationPort != nil {
				input.DestinationPort = probe.DestinationPort
			}
			if probe.PacketSize != nil {
				input.PacketSize = probe.PacketSize
			}
			if probe.Destination != nil {
				input.Destination = probe.Destination
			}
		}

		fmt.Println(input)

		_, err := conn.UpdateProbeWithContext(ctx, input)

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating CloudWatch Network Monitor Probe (%s): %s", d.Id(), err)
		}

		if _, err := WaitProbeUpdated(ctx, conn, d.Id(), d.Timeout(schema.TimeoutUpdate)); err != nil {
			return sdkdiag.AppendErrorf(diags, "waiting for CloudWatch Network Monitor Probe (%s) update: %s", d.Id(), err)
		}
	}

	return append(diags, resourceProbeRead(ctx, d, meta)...)
}

func resourceProbeDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics

	conn := meta.(*conns.AWSClient).NetworkMonitorConn(ctx)

	probeID, monitorName, parseErr := ProbeParseID(d.Id())
	if parseErr != nil {
		return sdkdiag.AppendErrorf(diags, "parsing CloudWatch Network Monitor Probe (%s) ID %s", d.Id(), parseErr)
	}

	log.Printf("[DEBUG] Deletin CloudWatch Network Monitor Probe: %s", d.Id())
	_, err := conn.DeleteProbeWithContext(ctx, &networkmonitor.DeleteProbeInput{
		MonitorName: &monitorName,
		ProbeId:     &probeID,
	})

	if tfawserr.ErrCodeEquals(err, networkmonitor.ErrCodeResourceNotFoundException) {
		return nil
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting CloudWatch Network Monitor Probe (%s): %s", d.Id(), err)
	}

	if _, err := WaitProbeDeleted(ctx, conn, d.Id(), d.Timeout(schema.TimeoutDelete)); err != nil {
		return sdkdiag.AppendErrorf(diags, "waiting for CloudWatch Network Monitor Probe (%s) delete: %s", d.Id(), err)
	}

	return nil
}

func flattenProbe(apiObject *networkmonitor.GetProbeOutput) []map[string]interface{} {
	if apiObject == nil {
		return nil
	}

	tfMap := map[string]interface{}{}

	if x := apiObject.AddressFamily; x != nil {
		tfMap["address_family"] = aws.ToString(x)
	}
	if x := apiObject.Destination; x != nil {
		tfMap["destination"] = aws.ToString(x)
	}
	if x := apiObject.DestinationPort; x != nil {
		tfMap["destination_port"] = aws.ToInt64(x)
	}
	if x := apiObject.PacketSize; x != nil {
		tfMap["packet_size"] = aws.ToInt64(x)
	}
	if x := apiObject.ProbeArn; x != nil {
		tfMap["probe_arn"] = aws.ToString(x)
	}
	if x := apiObject.ProbeId; x != nil {
		tfMap["probe_id"] = aws.ToString(x)
	}
	if x := apiObject.Protocol; x != nil {
		tfMap["protocol"] = aws.ToString(x)
	}
	if x := apiObject.SourceArn; x != nil {
		tfMap["source_arn"] = aws.ToString(x)
	}
	if x := apiObject.State; x != nil {
		tfMap["state"] = aws.ToString(x)
	}
	if x := apiObject.Tags; x != nil {
		tfMap["tags"] = flex.FlattenStringMap(x)
	}
	if x := apiObject.VpcId; x != nil {
		tfMap["vpc_id"] = aws.ToString(x)
	}

	return []map[string]interface{}{tfMap}
}

func ProbeParseID(id string) (string, string, error) {
	parts := strings.SplitN(id, ":", 2)

	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("unexpected format of ID (%s), expected probeID:monitorName", id)
	}

	return parts[0], parts[1], nil
}

func expandProbe(o map[string]interface{}, tags map[string]*string) *networkmonitor.ProbeInput_ {
	if o == nil {
		return nil
	}

	object := &networkmonitor.ProbeInput_{}

	if v, ok := o["destination"].(string); ok {
		object.Destination = aws.String(v)
	}

	if v, ok := o["protocol"].(string); ok {
		object.Protocol = aws.String(v)
	}

	if v, ok := o["source_arn"].(string); ok {
		object.SourceArn = aws.String(v)
	}

	if v, ok := o["destination_port"].(int); ok {
		object.DestinationPort = aws.Int64(int64(v))
	}

	if v, ok := o["packet_size"].(int); ok {
		object.PacketSize = aws.Int64(int64(v))
	}

	if tags != nil {
		object.Tags = tags
	}

	return object
}

func FindProbeByName(ctx context.Context, conn *networkmonitor.NetworkMonitor, id string) (*networkmonitor.GetProbeOutput, error) {
	probeID, monitorName, err := ProbeParseID(id)

	input := &networkmonitor.GetProbeInput{
		MonitorName: aws.String(monitorName),
		ProbeId:     aws.String(probeID),
	}

	output, err := conn.GetProbeWithContext(ctx, input)

	if tfawserr.ErrCodeEquals(err, networkmonitor.ErrCodeResourceNotFoundException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output, nil
}

func StatusProbeState(ctx context.Context, conn *networkmonitor.NetworkMonitor, id string) retry.StateRefreshFunc {
	return func() (interface{}, string, error) {
		output, err := FindProbeByName(ctx, conn, id)

		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return output, aws.ToString(output.State), nil
	}
}

func waitProbeCreated(ctx context.Context, conn *networkmonitor.NetworkMonitor, id string, timeout time.Duration) (*networkmonitor.Probe, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{networkmonitor.ProbeStatePending},
		Target:  []string{networkmonitor.ProbeStateActive},
		Timeout: timeout,
		Refresh: StatusProbeState(ctx, conn, id),
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*networkmonitor.Probe); ok {
		return output, err
	}

	return nil, err
}

func WaitProbeDeleted(ctx context.Context, conn *networkmonitor.NetworkMonitor, id string, timeout time.Duration) (*networkmonitor.Probe, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{networkmonitor.ProbeStateDeleting},
		Target:  []string{},
		Timeout: timeout,
		Refresh: StatusProbeState(ctx, conn, id),
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*networkmonitor.Probe); ok {
		return output, err
	}

	return nil, err
}

func WaitProbeUpdated(ctx context.Context, conn *networkmonitor.NetworkMonitor, id string, timeout time.Duration) (*networkmonitor.Probe, error) {
	stateConf := &retry.StateChangeConf{
		Pending: []string{networkmonitor.ProbeStatePending},
		Target:  []string{networkmonitor.ProbeStateActive},
		Timeout: timeout,
		Refresh: StatusProbeState(ctx, conn, id),
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*networkmonitor.Probe); ok {
		return output, err
	}

	return nil, err
}
