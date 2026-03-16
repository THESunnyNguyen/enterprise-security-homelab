# AWS EC2 & S3 Web Hosting Lab

A hands-on cloud infrastructure lab where I provisioned a Linux server on AWS EC2, configured a web server, and integrated cloud object storage via S3 — all accessed remotely through SSH from a Windows environment using WSL.

---

## 🛠️ Technologies & Tools Used

| Technology | Purpose |
|---|---|
| **AWS EC2** | Cloud virtual machine (Ubuntu 22.04) |
| **AWS S3** | Object storage for static assets |
| **Apache2** | HTTP web server |
| **SSH** | Secure remote access to EC2 |
| **WSL (Windows Subsystem for Linux)** | Linux terminal environment on Windows |
| **Ubuntu Linux** | Server OS and local terminal |
| **HTML** | Custom webpage creation |
| **IAM / Security Groups** | Access control and firewall configuration |
| **`.pem` Key Pairs** | RSA-based SSH authentication |

---

## 📋 Project Overview

This lab simulates a real-world cloud deployment workflow. Starting from zero, I set up a complete Linux environment on Windows, launched and secured a cloud server, deployed a web server, hosted a static webpage, and served images from a cloud storage bucket — the same core stack used in production web hosting environments.

---

## 🔧 Step-by-Step Walkthrough

### 1. Environment Setup — WSL on Windows

Before touching AWS, I needed a working SSH client. Rather than using PuTTY, I installed **Windows Subsystem for Linux (WSL)** to get a full Ubuntu terminal on my Windows machine.

**What I did:**
- Enabled the WSL and Windows Hypervisor Platform features via Windows Features (`Control Panel → Programs → Turn Windows features on or off`)
- Rebooted and installed **Ubuntu 22.04** from the Microsoft Store
- Initialized the Ubuntu environment, created a local user account, and ran a full system update:

```bash
sudo apt update -y && sudo apt upgrade -y
```

**Why it matters:** WSL provides a native Linux shell on Windows, enabling tools like `ssh`, `chmod`, and `scp` without any workarounds. This is how many developers work in cross-platform environments day to day.

---

### 2. EC2 Instance Launch & Security Configuration

With a terminal ready, I moved into AWS and provisioned a virtual machine using **EC2 (Elastic Compute Cloud)**.

**Configuration choices made:**
- **AMI:** Ubuntu Server 22.04 LTS (64-bit x86) — a stable, widely-used server OS
- **Instance type:** `t2.micro` — qualifies for the AWS Free Tier
- **Key pair:** Generated an RSA `.pem` key pair named `mykey` for passwordless SSH authentication
- **Security Group rules:**
  - Port 22 (SSH) — for remote terminal access
  - Port 80 (HTTP) — to allow web traffic to the Apache server

**Why it matters:** Security Groups act as a virtual firewall at the instance level. Opening only the ports you need (22 and 80 here, not 443 or others) is a core principle of least-privilege access — a foundational security concept in cloud architecture.

---

### 3. SSH Authentication & Remote Access

Once the instance was running, I connected to it remotely from WSL using the `.pem` private key downloaded during setup.

**Steps taken:**
```bash
# Copy the key from Windows filesystem into WSL home directory
cp /mnt/c/Users/USERNAME/Downloads/mykey.pem ~/mykey.pem

# Set strict file permissions — SSH refuses keys that are too permissive
chmod 400 ~/mykey.pem

# Connect to the EC2 instance
ssh -i ~/mykey.pem ubuntu@ec2-XX-XX-XX-XX.compute-1.amazonaws.com
```

**Why `chmod 400` matters:** SSH enforces that private keys are not readable by other users. Without this step, SSH throws a `Permissions too open` error and refuses to connect. This is a real security safeguard — a world-readable private key is effectively compromised.

---

### 4. Apache Web Server Installation & Verification

Once inside the EC2 instance, I installed and verified the **Apache2** HTTP server.

```bash
# Update package lists on the remote server
sudo apt update -y && sudo apt upgrade -y

# Install Apache
sudo apt install apache2 -y

# Verify the service is active
sudo systemctl status apache2
```

Expected output confirms the service is live:
```
● apache2.service - The Apache HTTP Server
     Active: active (running)
```

I then navigated to the instance's **public IPv4 address** in a browser and confirmed the default Apache landing page loaded — verifying that port 80 was open and Apache was serving traffic correctly.

---

### 5. S3 Bucket Creation & Public Object Hosting

With the server running, I set up **AWS S3** to host an image that would be embedded in the webpage.

**Configuration:**
- Created a bucket named `uNID-bucket` (bucket names must be globally unique across all AWS accounts)
- Enabled **ACLs (Access Control Lists)** under Object Ownership
- Disabled "Block all public access" to allow public object URLs
- Uploaded an image and used **Actions → Make Public via ACL** to expose it

The resulting public object URL follows this format:
```
https://uNID-bucket.s3.amazonaws.com/image.jpg
```

**Why it matters:** By default, S3 buckets and objects are private. Making an object public requires explicitly disabling bucket-level public access blocks *and* setting the object ACL — two separate permission layers. This reflects AWS's defense-in-depth approach to data protection.

---

### 6. Custom Webpage Deployment

With the S3 image URL in hand, I created a custom HTML page on the Apache server.

```bash
# Open a new file in Apache's web root
sudo nano /var/www/html/mypage.html
```

**HTML written:**
```html
<!DOCTYPE html>
<html>
<head>
  <title>uNID's Page</title>
</head>
<body>
  <h1>This is uNID's WebPage</h1>
  <p>Welcome to my page!</p>
  <img src="https://uNID-bucket.s3.amazonaws.com/image.jpg" alt="image description" />
</body>
</html>
```

The page was then accessible at:
```
http://PUBLIC_IP/mypage.html
```

This demonstrates a basic but complete full-stack cloud hosting setup: a compute instance (EC2) serving dynamic or static content that references assets stored in object storage (S3).

---

## 🧩 Challenges & How I Solved Them

### Challenge 1: SSH Key Permissions Error
**Problem:** After copying `mykey.pem` into WSL, SSH refused to connect with:
```
WARNING: UNPROTECTED PRIVATE KEY FILE!
Permissions 0644 for 'mykey.pem' are too open.
```
**Solution:** Running `chmod 400 ~/mykey.pem` restricted the file to owner-read-only, satisfying SSH's security requirement. The key lesson: file permission concepts from Linux apply directly to real security workflows.

---

### Challenge 2: Locating the .pem File from Windows in WSL
**Problem:** The `.pem` file downloaded to the Windows filesystem, which isn't directly in the WSL home directory.

**Solution:** WSL mounts the Windows filesystem under `/mnt/c/`, so the file was accessible at `/mnt/c/Users/USERNAME/Downloads/mykey.pem`. Using `cp` to move it into the WSL home directory (`~/`) kept it in a known, Unix-native location for clean SSH usage.

---

### Challenge 3: S3 Image Not Loading on Webpage
**Problem:** After uploading the image to S3 and embedding the URL, the image displayed a broken link.

**Solution:** The bucket had "Block all public access" disabled, but the *object itself* still had a private ACL. Going to the object → Actions → "Make Public via ACL" applied the correct object-level permission. This reinforced the distinction between bucket-level and object-level permissions in S3.

---

## 📚 Key Concepts Learned

**AWS Shared Responsibility Model**
AWS secures the underlying infrastructure (hardware, networking, hypervisors). The customer is responsible for what runs on top — OS patching, security group rules, S3 permissions, and data handling. S3 data leaks in the news are almost always a result of customer misconfiguration, not AWS infrastructure failures.

**AWS Regions & Availability Zones**
- A **Region** is a geographic cluster of data centers (e.g., `us-east-1` in Northern Virginia)
- An **Availability Zone** is a physically isolated data center within a region, with independent power and networking
- Deploying across multiple AZs protects against localized outages — a key principle of fault-tolerant architecture

**S3 Storage Classes & Lifecycle Policies**
S3 supports multiple storage tiers (Standard, Standard-IA, Glacier, etc.) with different cost and retrieval tradeoffs. Lifecycle policies can automatically transition objects to cheaper tiers after a defined period of inactivity — reducing storage costs significantly for data that is written once and rarely accessed, such as logs, backups, or archived media.

---

## 💡 Skills Gained

- Provisioning and configuring cloud virtual machines on AWS EC2
- Securing instances with key-pair authentication and security group firewall rules
- Navigating the Linux filesystem and running commands as a remote user via SSH
- Installing and verifying system services with `systemctl`
- Managing file permissions with `chmod`
- Creating and configuring AWS S3 buckets with public object access
- Writing and deploying a basic HTML page to an Apache web server
- Integrating cloud storage (S3) with a compute-hosted webpage (EC2)
- Working across the Windows/Linux boundary using WSL

---

## 🏗️ Architecture Diagram

```
┌─────────────────────────────────────────────────┐
│                   AWS Cloud                      │
│                                                  │
│   ┌──────────────┐        ┌──────────────────┐   │
│   │   EC2        │        │   S3 Bucket      │   │
│   │  (Ubuntu)    │        │                  │   │
│   │              │        │  image.jpg ──────┼───┼──► Public URL
│   │  Apache2  ───┼────────┼──► mypage.html   │   │
│   │  :80         │  img   │    embeds S3 URL │   │
│   └──────┬───────┘  src   └──────────────────┘   │
│          │                                        │
└──────────┼─────────────────────────────────────┘
           │ HTTP (port 80)
           │ SSH (port 22)
    ┌──────┴────────┐
    │  Local Machine│
    │  WSL / Ubuntu │
    │  ssh -i mykey │
    └───────────────┘
```

---

*Lab completed as part of a university server administration course. Demonstrates foundational AWS and Linux skills applicable to cloud engineering, DevOps, and systems administration roles.*
