There is a bug in Visual Studio when uploading to an Azure Web App for the first time.  It will not take the format:

  "ClientCertificates": [
      {
        "SourceType": "StoreWithThumbprint",
        "CertificateStorePath": "CurrentUser/My",
        "CertificateThumbprint": "11111111111111111111111111111111"
      }
    ]
  }

But it will take:

"CertificateThumbprint": "11111111111111111111111111111111"

"appsettings.json.vscode" is setup with this format for the certificates and can be used on the first push.
Then afterwards you will need to change the settings back to the original format and push again.

In case you need to make changes to program.cs I included the original in this folder.

Please make sure that you install all needed nuget packages prior to build.