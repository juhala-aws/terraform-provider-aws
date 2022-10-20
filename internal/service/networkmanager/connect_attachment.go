package networkmanager

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/networkmanager"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"

	// "github.com/hashicorp/terraform-provider-aws/internal/flex"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
)

func ResourceConnectAttachment() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceConnectAttachmentCreate,
		ReadWithoutTimeout:   resourceConnectAttachmentRead,
		UpdateWithoutTimeout: schema.NoopContext,
		DeleteWithoutTimeout: resourceConnectAttachmentDelete,

		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		CustomizeDiff: verify.SetTagsDiff,

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Update: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(10 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"attachment_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"attachment_policy_rule_number": {
				Type:     schema.TypeInt,
				Computed: true,
			},
			"attachment_type": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"core_network_arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"core_network_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(0, 50),
					validation.StringMatch(regexp.MustCompile(`^core-network-([0-9a-f]{8,17})$`), "Must start with core-network and then have 8 to 17 characters"),
				),
			},
			"edge_location": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(1, 63),
					validation.StringMatch(regexp.MustCompile(`[\s\S]*`), "Anything but whitespace"),
				),
			},
			"owner_account_id": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"resource_arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"segment_name": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"state": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"tags":     tftags.TagsSchema(),
			"tags_all": tftags.TagsSchemaComputed(),
			"transport_attachment_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.All(
					validation.StringLenBetween(0, 50),
					validation.StringMatch(regexp.MustCompile(`^attachment-([0-9a-f]{8,17})$`), "Must start with attachment- and then have 8 to 17 characters"),
				),
			},
			"options": {
				Type:     schema.TypeList,
				Required: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"protocol": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validation.StringInSlice([]string{"GRE"}, false),
						},
					},
				},
			},
		},
	}
}

func resourceConnectAttachmentCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).NetworkManagerConn
	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	tags := defaultTagsConfig.MergeTags(tftags.New(d.Get("tags").(map[string]interface{})))

	coreNetworkID := d.Get("core_network_id").(string)
	edgeLocation := d.Get("edge_location").(string)
	transportAttachmentID := d.Get("transport_attachment_id").(string)
	options := &networkmanager.ConnectAttachmentOptions{}

	if v, ok := d.GetOk("options"); ok && len(v.([]interface{})) > 0 && v.([]interface{})[0] != nil {
		options = expandConnectOptions(v.([]interface{})[0].(map[string]interface{}))
	}

	input := &networkmanager.CreateConnectAttachmentInput{
		CoreNetworkId:         aws.String(coreNetworkID),
		EdgeLocation:          aws.String(edgeLocation),
		TransportAttachmentId: aws.String(transportAttachmentID),
		Options:               options,
	}

	if len(tags) > 0 {
		input.Tags = Tags(tags.IgnoreAWS())
	}

	log.Printf("[DEBUG] Creating Network Manager Connect Attachment: %s", input)
	output, err := conn.CreateConnectAttachmentWithContext(ctx, input)

	if err != nil {
		return diag.Errorf("creating Network Manager Connect Attachment (%s) (%s): %s", transportAttachmentID, coreNetworkID, err)
	}

	d.SetId(aws.StringValue(output.ConnectAttachment.Attachment.AttachmentId))

	if _, err := waitConnectAttachmentCreated(ctx, conn, d.Id(), d.Timeout(schema.TimeoutCreate)); err != nil {
		return diag.Errorf("waiting for Network Manager Connect Attachment (%s) create: %s", d.Id(), err)
	}

	return resourceConnectAttachmentRead(ctx, d, meta)
}

func resourceConnectAttachmentRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).NetworkManagerConn
	defaultTagsConfig := meta.(*conns.AWSClient).DefaultTagsConfig
	ignoreTagsConfig := meta.(*conns.AWSClient).IgnoreTagsConfig

	fmt.Printf("Print ID: (%s)", d.Id())

	connectAttachment, err := FindConnectAttachmentByID(ctx, conn, d.Id())

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] Network Manager Connect Attachment %s not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	if err != nil {
		return diag.Errorf("reading Network Manager Connect Attachment (%s): %s", d.Id(), err)
	}

	a := connectAttachment.Attachment
	fmt.Println("Connect attachment")
	fmt.Println(a)
	arn := arn.ARN{
		Partition: meta.(*conns.AWSClient).Partition,
		Service:   "networkmanager",
		AccountID: meta.(*conns.AWSClient).AccountID,
		Resource:  fmt.Sprintf("attachment/%s", d.Id()),
	}.String()
	d.Set("arn", arn)
	d.Set("attachment_policy_rule_number", a.AttachmentPolicyRuleNumber)
	d.Set("attachment_id", a.AttachmentId)
	d.Set("attachment_type", a.AttachmentType)
	d.Set("core_network_arn", a.CoreNetworkArn)
	d.Set("core_network_id", a.CoreNetworkId)
	d.Set("owner_account_id", a.OwnerAccountId)
	d.Set("resource_arn", a.ResourceArn)
	d.Set("segment_name", a.SegmentName)
	d.Set("state", a.State)

	tags := KeyValueTags(a.Tags).IgnoreAWS().IgnoreConfig(ignoreTagsConfig)

	//lintignore:AWSR002
	if err := d.Set("tags", tags.RemoveDefaultConfig(defaultTagsConfig).Map()); err != nil {
		return diag.Errorf("Setting tags: %s", err)
	}

	if err := d.Set("tags_all", tags.Map()); err != nil {
		return diag.Errorf("setting tags_all: %s", err)
	}

	return nil
}

func resourceConnectAttachmentDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	conn := meta.(*conns.AWSClient).NetworkManagerConn

	if state := d.Get("state").(string); state == networkmanager.AttachmentStatePendingAttachmentAcceptance || state == networkmanager.AttachmentStatePendingTagAcceptance {
		return diag.Errorf("cannot delete Network Manager Connect Attachment (%s) in %s state", d.Id(), state)
	}

	log.Printf("[DEBUG] Deleting Network Manager Connect Attachment: %s", d.Id())
	_, err := conn.DeleteAttachmentWithContext(ctx, &networkmanager.DeleteAttachmentInput{
		AttachmentId: aws.String(d.Id()),
	})

	if tfawserr.ErrCodeEquals(err, networkmanager.ErrCodeResourceNotFoundException) {
		return nil
	}

	if err != nil {
		return diag.Errorf("deleting Network Manager Connect Attachment (%s): %s", d.Id(), err)
	}

	if _, err := waitConnectAttachmentDeleted(ctx, conn, d.Id(), d.Timeout(schema.TimeoutDelete)); err != nil {
		return diag.Errorf("waiting for Network Manager Connect Attachment (%s) delete: %s", d.Id(), err)
	}

	return nil
}

func FindConnectAttachmentByID(ctx context.Context, conn *networkmanager.NetworkManager, id string) (*networkmanager.ConnectAttachment, error) {
	input := &networkmanager.GetConnectAttachmentInput{
		AttachmentId: aws.String(id),
	}

	output, err := conn.GetConnectAttachmentWithContext(ctx, input)

	if tfawserr.ErrCodeEquals(err, networkmanager.ErrCodeResourceNotFoundException) {
		return nil, &resource.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil || output.ConnectAttachment == nil || output.ConnectAttachment.Attachment == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output.ConnectAttachment, nil
}

func StatusConnectAttachmentState(ctx context.Context, conn *networkmanager.NetworkManager, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		output, err := FindConnectAttachmentByID(ctx, conn, id)

		if tfresource.NotFound(err) {
			return nil, "", nil
		}

		if err != nil {
			return nil, "", err
		}

		return output, aws.StringValue(output.Attachment.State), nil
	}
}

func waitConnectAttachmentCreated(ctx context.Context, conn *networkmanager.NetworkManager, id string, timeout time.Duration) (*networkmanager.ConnectAttachment, error) { //nolint:unparam
	stateConf := &resource.StateChangeConf{
		Pending: []string{networkmanager.AttachmentStateCreating, networkmanager.AttachmentStatePendingNetworkUpdate},
		Target:  []string{networkmanager.AttachmentStateAvailable, networkmanager.AttachmentStatePendingAttachmentAcceptance},
		Timeout: timeout,
		Refresh: StatusConnectAttachmentState(ctx, conn, id),
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*networkmanager.ConnectAttachment); ok {
		return output, err
	}

	return nil, err
}

func waitConnectAttachmentDeleted(ctx context.Context, conn *networkmanager.NetworkManager, id string, timeout time.Duration) (*networkmanager.ConnectAttachment, error) {
	stateConf := &resource.StateChangeConf{
		Pending:        []string{networkmanager.AttachmentStateDeleting},
		Target:         []string{},
		Timeout:        timeout,
		Refresh:        StatusConnectAttachmentState(ctx, conn, id),
		NotFoundChecks: 1,
	}

	outputRaw, err := stateConf.WaitForStateContext(ctx)

	if output, ok := outputRaw.(*networkmanager.ConnectAttachment); ok {
		return output, err
	}

	return nil, err
}

func expandConnectOptions(o map[string]interface{}) *networkmanager.ConnectAttachmentOptions {
	if o == nil {
		return nil
	}

	object := &networkmanager.ConnectAttachmentOptions{}

	if v, ok := o["protocol"].(string); ok {
		object.Protocol = aws.String(v)
	}

	return object
}
