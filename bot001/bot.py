#!/usr/local/bin/python3
import logging
import boto3
#import sonrai.platform.aws.arn
import json


def run(ctx):
    # Get data for bot from ctx
    data_enum = ctx.get_policy_evidence_data()

    # loop for each analytic data result
    #for instance_id in ['i-0a2409638ae392d85']: 
    for data in data_enum:
        # Get instance ID
        resource_arn = sonrai.platform.aws.arn.parse(data['resourceId'])
        instance_id = resource_arn \
            .assert_service("ec2") \
            .assert_type("instance") \
            .name

        
        
        # Create AWS identity and access management client
        ec2_client = boto3.client('ec2')
        ec2_resource = boto3.resource('ec2')

        # Verify instance exists
        instance_details = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        # Stop EC2 instance.
        logging.info("Stopping EC2 instance: {} ".format(instance_id))
        ec2_client.stop_instances(InstanceIds=[instance_id])

        # Get VPC for instance
        vpc_id = instance_details["Reservations"][0]["Instances"][0]["VpcId"]
        
        # Create deny-all security group in VPC if it does not already exist.
        response  = ec2_client.describe_security_groups(Filters=[{'Name':'vpc-id','Values':[vpc_id]},{'Name':'group-name','Values':['sonrai-deny-all']}])
        if response["SecurityGroups"]:
            group_id = response["SecurityGroups"][0]["GroupId"]
            logging.info("Found sonrai-deny-all security group with id: {}".format(group_id))
        else:
            new_group = ec2_client.create_security_group(
                   Description='Deny-All SG for Sonrai Remediation Bots',
                   GroupName='sonrai-deny-all',
                   VpcId=vpc_id,
                   )
            group_id = new_group['GroupId'] 
            logging.info("Created sonrai-deny-all security group with id: {}".format(group_id))

        # Make absolutely certain that the deny-all group has no ingress/egress rules
        sg = ec2_resource.SecurityGroup(group_id)
        if sg.ip_permissions:
          sg.revoke_ingress(IpPermissions=sg.ip_permissions)
        if sg.ip_permissions_egress:
          sg.revoke_egress(IpPermissions=sg.ip_permissions_egress)

        # Iterate through network interfaces, and remove current security groups from EC2 instance by specifying the group list, including only the new deny-all group.
        for network_interface in  instance_details["Reservations"][0]["Instances"][0]["NetworkInterfaces"]:
          logging.info("Assigning deny-all security group to ENI with id: {}".format(network_interface["NetworkInterfaceId"]))
          response = ec2_client.modify_network_interface_attribute(NetworkInterfaceId=network_interface["NetworkInterfaceId"],Groups=[group_id]) 

