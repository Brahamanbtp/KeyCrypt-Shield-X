variable "name" {
  description = "Base name for resources"
  type        = string
  default     = "keycrypt"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnets" {
  description = "List of public subnets CIDRs"
  type        = list(string)
  default     = ["10.0.0.0/24", "10.0.1.0/24"]
}

variable "private_subnets" {
  description = "List of private subnets CIDRs"
  type        = list(string)
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "instance_type" {
  description = "Instance type for app nodes"
  type        = string
  default     = "t3.medium"
}

variable "asg_min_size" {
  type    = number
  default = 3
}

variable "asg_max_size" {
  type    = number
  default = 10
}

variable "rds_allocated_storage" {
  type    = number
  default = 100
}

variable "rds_instance_class" {
  type    = string
  default = "db.t3.medium"
}

variable "redis_node_type" {
  type    = string
  default = "cache.t3.medium"
}

variable "s3_versioning" {
  type    = bool
  default = true
}

variable "allowed_ingress_cidr" {
  description = "CIDR blocks allowed to access ALB (e.g., corporate NAT)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
