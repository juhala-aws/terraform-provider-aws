package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkmonitor"
	awstypes "github.com/aws/aws-sdk-go-v2/service/networkmonitor/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"

	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

const (
	MonitorTimeout               = time.Minute * 10
	ResNameNetworkMonitorMonitor = "CloudWatch Network Monitor Monitor"
)

// @FrameworkResource(name="CloudWatch Network Monitor Monitor")
func newResourceNetworkMonitorMonitor(context.Context) (resource.ResourceWithConfigure, error) {
	return &resourceNetworkMonitorMonitor{}, nil
}

type resourceNetworkMonitorMonitor struct {
	framework.ResourceWithConfigure
}

func (r *resourceNetworkMonitorMonitor) Metadata(_ context.Context, request resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "aws_networkmonitor_monitor"
}

func (r *resourceNetworkMonitorMonitor) Schema(ctx context.Context, request resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": framework.IDAttribute(),
			"arn": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"aggregation_period": schema.Int64Attribute{
				Optional: true,
				Validators: []validator.Int64{
					int64validator.OneOf(30, 60),
				},
			},
			"created_at": schema.Int64Attribute{
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"modified_at": schema.Int64Attribute{
				Computed: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"monitor_name": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile("[a-zA-Z0-9_-]+"), "Must match [a-zA-Z0-9_-]+"),
					stringvalidator.LengthBetween(1, 255),
				},
			},
			"state": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			names.AttrTags:    tftags.TagsAttribute(),
			names.AttrTagsAll: tftags.TagsAttributeComputedOnly(),
		},
		Blocks: map[string]schema.Block{
			"probes": schema.ListNestedBlock{
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"address_family": schema.StringAttribute{
							Computed: true,
						},
						"created_at": schema.Int64Attribute{
							Computed: true,
						},
						"destination": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.LengthBetween(1, 255),
							},
						},
						"destination_port": schema.Int64Attribute{
							Optional: true,
							Validators: []validator.Int64{
								int64validator.Between(0, 65536),
							},
						},
						"modified_at": schema.Int64Attribute{
							Computed: true,
						},
						"packet_size": schema.Int64Attribute{
							Optional: true,
							Validators: []validator.Int64{
								int64validator.Between(56, 8500),
							},
						},
						"probe_arn": schema.StringAttribute{
							Computed: true,
						},
						"probe_id": schema.StringAttribute{
							Computed: true,
						},
						"probe_tags": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
						},
						"protocol": schema.StringAttribute{
							Required: true,
							Validators: []validator.String{
								stringvalidator.LengthBetween(20, 2048),
								stringvalidator.RegexMatches(regexp.MustCompile("arn:.*"), "Must match pattern arn:*"),
							},
						},
						"source_arn": schema.StringAttribute{
							Required: true,
						},
						"state": schema.StringAttribute{
							Computed: true,
						},
						"vpc_id": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (r *resourceNetworkMonitorMonitor) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().NetworkMonitorClient(ctx)

	var plan resourceNetworkMonitorMonitorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var probes []monitorProbeConfigModel
	resp.Diagnostics.Append(plan.Probes.ElementsAs(ctx, &probes, false)...)

	probeConfig := expandMonitorProbeConfig(ctx, probes, resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	input := networkmonitor.CreateMonitorInput{
		MonitorName:       plan.MonitorName.ValueStringPointer(),
		AggregationPeriod: plan.AggregationPeriod.ValueInt64Pointer(),
		Probes:            probeConfig,
		Tags:              flex.ExpandFrameworkStringValueMap(ctx, plan.Tags),
	}

	_, err := conn.CreateMonitor(ctx, &input)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionCreating, ResNameNetworkMonitorMonitor, plan.MonitorName.String(), nil),
			err.Error(),
		)
		return
	}

	var out *networkmonitor.GetMonitorOutput
	retryErr := retry.RetryContext(ctx, MonitorTimeout, func() *retry.RetryError {
		var err error
		in := networkmonitor.GetMonitorInput{MonitorName: plan.MonitorName.ValueStringPointer()}
		out, err = conn.GetMonitor(ctx, &in)
		if out.State == awstypes.MonitorStatePending {
			return retry.RetryableError(create.Error(names.NetworkMonitor, create.ErrActionWaitingForCreation, ResNameNetworkMonitorMonitor, plan.MonitorName.ValueString(), err))
		}
		return nil
	})
	if retryErr != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionCreating, ResNameNetworkMonitorMonitor, plan.MonitorName.ValueString(), nil),
			err.Error(),
		)
		return
	}

	state := plan
	// If there are probes. Wait for all of those to be ready
	if out.Probes != nil {
		for _, p := range out.Probes {
			retryErr := retry.RetryContext(ctx, ProbeTimeout, func() *retry.RetryError {
				var err error
				var probeOut *networkmonitor.GetProbeOutput
				in := networkmonitor.GetProbeInput{
					MonitorName: plan.MonitorName.ValueStringPointer(),
					ProbeId:     p.ProbeId,
				}
				probeOut, err = conn.GetProbe(ctx, &in)
				if probeOut.State == awstypes.ProbeStateInactive || probeOut.State == awstypes.ProbeStatePending {
					return retry.RetryableError(create.Error(names.NetworkMonitor, create.ErrActionWaitingForCreation, ResNameNetworkMonitorMonitor, state.ID.String(), err))
				}
				return nil
			})
			if retryErr != nil {
				resp.Diagnostics.AddError(
					create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionCreating, ResNameNetworkMonitorProbe, *p.ProbeId, nil),
					err.Error(),
				)
				return
			}
		}
	}

	//refresh monitor to get finished state as not all values are returned with createMonitorOutput
	out, err = FindMonitorByName(ctx, plan.MonitorName.ValueString(), conn)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionCreating, ResNameNetworkMonitorMonitor, plan.MonitorName.ValueString(), nil),
			err.Error(),
		)
		return
	}

	p, d := flattenMonitorProbeConfig(ctx, &out.Probes)
	resp.Diagnostics.Append(d...)
	state.Probes = p

	state.ID = flex.StringToFramework(ctx, out.MonitorName)
	state.AggregationPeriod = flex.Int64ToFramework(ctx, out.AggregationPeriod)
	state.MonitorName = flex.StringToFramework(ctx, out.MonitorName)
	state.Arn = flex.StringToFramework(ctx, out.MonitorArn)
	state.State = flex.StringToFramework(ctx, (*string)(&out.State))
	state.CreatedAt = flex.Int64ToFramework(ctx, (aws.Int64(out.CreatedAt.Unix())))
	state.ModifiedAt = flex.Int64ToFramework(ctx, (aws.Int64(out.ModifiedAt.Unix())))

	setTagsOut(ctx, flex.ExpandFrameworkStringValueMap(ctx, plan.Tags))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceNetworkMonitorMonitor) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().NetworkMonitorClient(ctx)

	var state resourceNetworkMonitorMonitorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	output, err := FindMonitorByName(ctx, state.ID.ValueString(), conn)
	var nfe *retry.NotFoundError
	var ere *tfresource.EmptyResultError
	if errors.As(err, &nfe) || errors.As(err, &ere) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionReading, ResNameNetworkMonitorMonitor, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	state.AggregationPeriod = flex.Int64ToFramework(ctx, output.AggregationPeriod)
	state.MonitorName = flex.StringToFramework(ctx, output.MonitorName)
	state.Arn = flex.StringToFramework(ctx, output.MonitorArn)
	state.State = flex.StringToFramework(ctx, (*string)(&output.State))
	state.CreatedAt = flex.Int64ToFramework(ctx, (aws.Int64(output.CreatedAt.Unix())))
	state.ModifiedAt = flex.Int64ToFramework(ctx, (aws.Int64(output.ModifiedAt.Unix())))

	// Only update probes if those are already in the state. This is avoid changes in state when probe is created separately.

	if output.Probes != nil {
		// This is a read for import. Get also probes.
		probes, d := flattenMonitorProbeConfig(ctx, &output.Probes)
		resp.Diagnostics.Append(d...)
		state.Probes = probes
	}

	setTagsOut(ctx, output.Tags)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceNetworkMonitorMonitor) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	conn := r.Meta().NetworkMonitorClient(ctx)

	var plan, state resourceNetworkMonitorMonitorModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.AggregationPeriod.Equal(state.AggregationPeriod) {
		input := networkmonitor.UpdateMonitorInput{
			MonitorName:       plan.MonitorName.ValueStringPointer(),
			AggregationPeriod: plan.AggregationPeriod.ValueInt64Pointer(),
		}

		_, err := conn.UpdateMonitor(ctx, &input)
		if err != nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionUpdating, ResNameNetworkMonitorMonitor, state.ID.String(), nil),
				err.Error(),
			)
			return
		}
	}
	setTagsOut(ctx, flex.ExpandFrameworkStringValueMap(ctx, plan.Tags))

	//refresh monitor to get finished state
	out, err := FindMonitorByName(ctx, plan.MonitorName.ValueString(), conn)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionCreating, ResNameNetworkMonitorMonitor, plan.MonitorName.ValueString(), nil),
			err.Error(),
		)
		return
	}

	state.AggregationPeriod = flex.Int64ToFramework(ctx, out.AggregationPeriod)
	state.MonitorName = flex.StringToFramework(ctx, out.MonitorName)
	state.Arn = flex.StringToFramework(ctx, out.MonitorArn)
	state.State = flex.StringToFramework(ctx, (*string)(&out.State))
	if out.Probes != nil {
		probes, d := flattenMonitorProbeConfig(ctx, &out.Probes)
		resp.Diagnostics.Append(d...)
		state.Probes = probes
	}
	state.CreatedAt = flex.Int64ToFramework(ctx, (aws.Int64(out.CreatedAt.Unix())))
	state.ModifiedAt = flex.Int64ToFramework(ctx, (aws.Int64(out.ModifiedAt.Unix())))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceNetworkMonitorMonitor) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().NetworkMonitorClient(ctx)

	var state resourceNetworkMonitorMonitorModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	output, err := FindMonitorByName(ctx, state.ID.ValueString(), conn)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionDeleting, ResNameNetworkMonitorMonitor, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	if output.Probes != nil {
		for _, p := range output.Probes {
			input := networkmonitor.DeleteProbeInput{
				MonitorName: state.MonitorName.ValueStringPointer(),
				ProbeId:     p.ProbeId,
			}

			_, err = conn.DeleteProbe(ctx, &input)

			retryErr := retry.RetryContext(ctx, ProbeTimeout, func() *retry.RetryError {
				probeID := fmt.Sprintf("%s:%s", *p.ProbeId, state.ID.ValueString())
				out, err := FindProbeByID(ctx, conn, probeID)
				if err != nil {
					var nfe *awstypes.ResourceNotFoundException
					if errors.As(err, &nfe) {
						return nil
					}
				}

				if out.State == awstypes.ProbeStateDeleting {
					return retry.RetryableError(create.Error(names.NetworkMonitor, create.ErrActionWaitingForDeletion, ResNameNetworkMonitorProbe, state.ID.String(), err))
				}
				return nil
			})

			if retryErr != nil {
				resp.Diagnostics.AddError(
					create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionDeleting, ResNameNetworkMonitorMonitor, *p.ProbeId, nil),
					err.Error(),
				)
				return
			}
		}
	}

	input := networkmonitor.DeleteMonitorInput{
		MonitorName: flex.StringFromFramework(ctx, state.MonitorName),
	}
	_, err = conn.DeleteMonitor(ctx, &input)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionDeleting, ResNameNetworkMonitorMonitor, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	var out *networkmonitor.GetMonitorOutput
	retryErr := retry.RetryContext(ctx, MonitorTimeout, func() *retry.RetryError {
		var err error
		out, err = FindMonitorByName(ctx, state.ID.ValueString(), conn)
		if err != nil {
			var nfe *awstypes.ResourceNotFoundException
			if errors.As(err, &nfe) {
				return nil
			}
		}
		if out.State == awstypes.MonitorStateDeleting {
			return retry.RetryableError(create.Error(names.NetworkMonitor, create.ErrActionWaitingForDeletion, ResNameNetworkMonitorMonitor, state.ID.String(), err))
		}
		return nil
	})
	if retryErr != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.NetworkMonitor, create.ErrActionDeleting, ResNameNetworkMonitorMonitor, state.ID.String(), nil),
			err.Error(),
		)
		return
	}

}

func FindMonitorByName(ctx context.Context, name string, conn *networkmonitor.Client) (*networkmonitor.GetMonitorOutput, error) {
	input := &networkmonitor.GetMonitorInput{
		MonitorName: &name,
	}

	output, err := conn.GetMonitor(ctx, input)
	if err != nil {
		var nfe *awstypes.ResourceNotFoundException
		if errors.As(err, &nfe) {
			return nil, &retry.NotFoundError{
				LastError:   err,
				LastRequest: input,
			}
		}

		return nil, err
	}

	if output == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output, nil
}

func (r *resourceNetworkMonitorMonitor) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	r.SetTagsAll(ctx, req, resp)
}

func (r *resourceNetworkMonitorMonitor) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func flattenMonitorProbeConfig(ctx context.Context, object *[]awstypes.Probe) (types.List, diag.Diagnostics) {

	var diags diag.Diagnostics
	probeType := types.ObjectType{AttrTypes: monitorProbeConfigTypes}

	if object == nil {
		return types.ListValueMust(probeType, []attr.Value{}), diags
	}

	probes := []attr.Value{}

	for _, v := range *object {
		t := map[string]attr.Value{
			"address_family":   flex.StringToFramework(ctx, (*string)(&v.AddressFamily)),
			"created_at":       flex.Int64ToFramework(ctx, (aws.Int64(11111))),
			"destination":      flex.StringToFramework(ctx, v.Destination),
			"destination_port": flex.Int64ToFramework(ctx, aws.Int64(int64(*v.DestinationPort))),
			"modified_at":      flex.Int64ToFramework(ctx, (aws.Int64(11111))),
			"packet_size":      flex.Int64ToFramework(ctx, aws.Int64(int64(*v.PacketSize))),
			"probe_arn":        flex.StringToFramework(ctx, v.ProbeArn),
			"probe_id":         flex.StringToFramework(ctx, v.ProbeId),
			"probe_tags":       flex.FlattenFrameworkStringValueMap(ctx, v.Tags),
			"protocol":         flex.StringToFramework(ctx, (*string)(&v.Protocol)),
			"source_arn":       flex.StringToFramework(ctx, v.SourceArn),
			"state":            flex.StringToFramework(ctx, (*string)(&v.State)),
			"vpc_id":           flex.StringToFramework(ctx, v.VpcId),
		}
		objVal, d := types.ObjectValue(monitorProbeConfigTypes, t)
		diags.Append(d...)
		probes = append(probes, objVal)
	}

	listVal, d := types.ListValue(probeType, probes)

	diags.Append(d...)

	return listVal, diags
}

var monitorProbeConfigTypes = map[string]attr.Type{
	"address_family":   types.StringType,
	"created_at":       types.Int64Type,
	"destination":      types.StringType,
	"destination_port": types.Int64Type,
	"modified_at":      types.Int64Type,
	"packet_size":      types.Int64Type,
	"probe_arn":        types.StringType,
	"probe_id":         types.StringType,
	"probe_tags":       types.MapType{ElemType: types.StringType},
	"protocol":         types.StringType,
	"source_arn":       types.StringType,
	"state":            types.StringType,
	"vpc_id":           types.StringType,
}

var probeTagsType = []map[string]attr.Type{}

type resourceNetworkMonitorMonitorModel struct {
	ID                types.String `tfsdk:"id"`
	Arn               types.String `tfsdk:"arn"`
	AggregationPeriod types.Int64  `tfsdk:"aggregation_period"`
	CreatedAt         types.Int64  `tfsdk:"created_at"`
	ModifiedAt        types.Int64  `tfsdk:"modified_at"`
	MonitorName       types.String `tfsdk:"monitor_name"`
	Probes            types.List   `tfsdk:"probes"`
	State             types.String `tfsdk:"state"`
	Tags              types.Map    `tfsdk:"tags"`
	TagsAll           types.Map    `tfsdk:"tags_all"`
}

type monitorProbeConfigModel struct {
	AddressFamily   types.String `tfsdk:"address_family"`
	CreatedAt       types.Int64  `tfsdk:"created_at"`
	Destination     types.String `tfsdk:"destination"`
	DestinationPort types.Int64  `tfsdk:"destination_port"`
	ModifiedAt      types.Int64  `tfsdk:"modified_at"`
	PacketSize      types.Int64  `tfsdk:"packet_size"`
	ProbeArn        types.String `tfsdk:"probe_arn"`
	ProbeId         types.String `tfsdk:"probe_id"`
	ProbeTags       types.Map    `tfsdk:"probe_tags"`
	Protocol        types.String `tfsdk:"protocol"`
	SourceArn       types.String `tfsdk:"source_arn"`
	State           types.String `tfsdk:"state"`
	VpcId           types.String `tfsdk:"vpc_id"`
}

func expandMonitorProbeConfig(ctx context.Context, object []monitorProbeConfigModel, diags diag.Diagnostics) []awstypes.CreateMonitorProbeInput {
	if len(object) == 0 {
		return nil
	}

	apiObject := make([]awstypes.CreateMonitorProbeInput, len(object))

	for index, v := range object {
		t := awstypes.CreateMonitorProbeInput{
			Destination:     v.Destination.ValueStringPointer(),
			DestinationPort: flex.Int32FromFramework(ctx, v.DestinationPort),
			PacketSize:      flex.Int32FromFramework(ctx, v.PacketSize),
			Protocol:        awstypes.Protocol(*aws.String(v.Protocol.ValueString())),
			SourceArn:       v.SourceArn.ValueStringPointer(),
			ProbeTags:       flex.ExpandFrameworkStringValueMap(ctx, v.ProbeTags),
		}
		apiObject[index] = t
	}

	return apiObject
}
