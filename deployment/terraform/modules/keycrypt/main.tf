// Terraform AWS module: KeyCrypt core infrastructure

locals {
  public_count  = length(var.public_subnets)
  private_count = length(var.private_subnets)
  name_prefix   = var.name
}

resource "aws_vpc" "this" {
  cidr_block = var.vpc_cidr
  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.this.id
  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count                   = local.public_count
  vpc_id                  = aws_vpc.this.id
  cidr_block              = element(var.public_subnets, count.index)
  map_public_ip_on_launch = true
  tags = { Name = "${local.name_prefix}-public-${count.index}" }
}

resource "aws_subnet" "private" {
  count  = local.private_count
  vpc_id = aws_vpc.this.id
  cidr_block = element(var.private_subnets, count.index)
  tags = { Name = "${local.name_prefix}-private-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${local.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public_assoc" {
  count          = local.public_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "alb" {
  name   = "${local.name_prefix}-alb-sg"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidr
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidr
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${local.name_prefix}-alb-sg" }
}

resource "aws_security_group" "app" {
  name   = "${local.name_prefix}-app-sg"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${local.name_prefix}-app-sg" }
}

resource "aws_security_group" "db" {
  name   = "${local.name_prefix}-db-sg"
  vpc_id = aws_vpc.this.id
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  egress { from_port = 0; to_port = 0; protocol = "-1"; cidr_blocks = ["0.0.0.0/0"] }
  tags = { Name = "${local.name_prefix}-db-sg" }
}

resource "aws_kms_key" "data" {
  description = "KMS key for envelope encryption for ${var.name}"
  deletion_window_in_days = 30
  tags = { Name = "${local.name_prefix}-kms" }
}

resource "aws_s3_bucket" "data" {
  bucket = "${local.name_prefix}-data-${random_id.bucket_hex.hex}"
  acl    = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "aws:kms"
        kms_master_key_id = aws_kms_key.data.key_id
      }
    }
  }
  versioning { enabled = var.s3_versioning }
  tags = { Name = "${local.name_prefix}-s3" }
}

resource "random_id" "bucket_hex" {
  byte_length = 4
}

resource "aws_db_subnet_group" "db_subnets" {
  name       = "${local.name_prefix}-db-subnet-group"
  subnet_ids = [for s in aws_subnet.private : s.id]
}

resource "aws_db_instance" "postgres" {
  identifier              = "${local.name_prefix}-postgres"
  allocated_storage       = var.rds_allocated_storage
  engine                  = "postgres"
  instance_class          = var.rds_instance_class
  name                    = "keycryptdb"
  username                = "keycrypt_admin"
  password                = random_password.db_password.result
  db_subnet_group_name    = aws_db_subnet_group.db_subnets.name
  vpc_security_group_ids  = [aws_security_group.db.id]
  skip_final_snapshot     = true
  tags = { Name = "${local.name_prefix}-rds" }
}

resource "random_password" "db_password" {
  length  = 16
  special = true
}

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name_prefix}-redis-subnet-group"
  subnet_ids = [for s in aws_subnet.private : s.id]
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = "${local.name_prefix}-redis"
  replication_group_description = "Redis cluster for ${var.name}"
  node_type                     = var.redis_node_type
  number_cache_clusters         = 1
  subnet_group_name             = aws_elasticache_subnet_group.redis.name
  security_group_ids            = [aws_security_group.db.id]
  tags = { Name = "${local.name_prefix}-redis" }
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/aws/${local.name_prefix}/app"
  retention_in_days = 30
}

resource "aws_lb" "alb" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = [for s in aws_subnet.public : s.id]
  security_groups    = [aws_security_group.alb.id]
}

resource "aws_autoscaling_group" "app_asg" {
  name                      = "${local.name_prefix}-asg"
  max_size                  = var.asg_max_size
  min_size                  = var.asg_min_size
  desired_capacity          = var.asg_min_size
  vpc_zone_identifier       = [for s in aws_subnet.private : s.id]
  health_check_type         = "ELB"
  tags = [{ key = "Name", value = "${local.name_prefix}-asg", propagate_at_launch = true }]
}

resource "aws_ecs_cluster" "ecs" {
  name = "${local.name_prefix}-ecs-cluster"
}

// Outputs for convenience
