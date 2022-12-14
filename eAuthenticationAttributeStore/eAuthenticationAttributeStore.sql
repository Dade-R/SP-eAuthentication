USE [eAuthAttributeStore]
GO
/****** Object:  Table [dbo].[Claims] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Claims](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[UserID] [int] NOT NULL,
	[ClaimType] [nvarchar](255) NOT NULL,
	[ClaimValue] [nvarchar](255) NOT NULL,
	[DateTime] [datetime] NOT NULL
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[ClaimTypeMapping] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ClaimTypeMapping](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[ClaimType] [nvarchar](255) NOT NULL,
	[UserPropertyName] [nvarchar](255) NOT NULL,
	[isIdentity] [bit] NOT NULL,
	[isRole] [bit] NOT NULL,
	[isDisplayName] [bit] NOT NULL,
	[isEmail] [bit] NOT NULL
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Messages] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Messages](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Created] [datetime] NOT NULL,
	[Message] [text] NULL,
	[Severity] [nvarchar](50) NULL,
	[Server] [nvarchar](50) NULL,
	[StackTrace] [text] NULL,
	[ExceptionMessage] [text] NULL,
	[InnerExceptionStackTrace] [text] NULL,
	[SessionUser] [nvarchar](255) NULL,
	[EventID] [int] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[TOUAcceptHistory] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TOUAcceptHistory](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[UserID] [int] NOT NULL,
	[AcceptanceDate] [datetime] NOT NULL
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[UserProperties] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[UserProperties](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[UserID] [int] NOT NULL,
	[ClaimTypeMappingID] [int] NOT NULL,
	[PropertyName] [nvarchar](255) NOT NULL,
	[PropertyValue] [nvarchar](255) NOT NULL
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[UserRoles] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[UserRoles](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[UserID] [int] NOT NULL,
	[ClaimTypeMappingID] [int] NOT NULL,
	[RoleName] [nvarchar](255) NOT NULL,
	[CreateDate] [datetime] NOT NULL,
	[LastModifiedDate] [datetime] NOT NULL,
	[Active] [bit] NOT NULL
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Users] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Users](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[Identity] [nvarchar](255) NOT NULL,
	[EmailAddress] [nvarchar](255) NULL,
	[DisplayName] [nvarchar](255) NULL,
	[isApproved] [bit] NOT NULL,
	[isSecurityApproved] [bit] NOT NULL,
	[isTOUAccepted] [bit] NOT NULL,
	[CreateDate] [datetime] NOT NULL,
	[TOUAcceptedDate] [datetime] NULL,
	[LastModifiedDate] [datetime] NOT NULL,
	[LastLoginDate] [datetime] NULL,
	[LoginCount] [bigint] NULL
) ON [PRIMARY]

GO
/****** Object:  StoredProcedure [dbo].[AcceptTOU] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[AcceptTOU]
	@UserID INT
AS
BEGIN
	SET NOCOUNT ON;

	IF @UserID IS NOT NULL
		BEGIN
			UPDATE [Users] SET [TOUAcceptedDate] = GETDATE(), [isTOUAccepted] = 1 WHERE ID = @UserID;
			INSERT INTO [TOUAcceptHistory] ([UserID], [AcceptanceDate]) VALUES (@UserID, GETDATE());
		END
	 
SELECT * FROM [Users] WHERE [ID] = @UserID;

END
GO
/****** Object:  StoredProcedure [dbo].[GetAllRoles] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO


CREATE PROCEDURE [dbo].[GetAllRoles]
AS
BEGIN
	SET NOCOUNT ON;

	SELECT UR.[RoleName] FROM [dbo].[UserRoles] UR
	INNER JOIN [dbo].[ClaimTypeMapping] CTP ON CTP.isRole = 1
	WHERE UR.[ClaimTypeMappingID] = CTP.[ID] AND UR.[Active] = 1
	GROUP BY UR.[RoleName]
	ORDER BY UR.[RoleName]
	
END

GO
/****** Object:  StoredProcedure [dbo].[GetIdentityClaimType] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[GetIdentityClaimType]
AS
BEGIN
	SET NOCOUNT ON;

	SELECT TOP 1 [ClaimType] FROM [ClaimTypeMapping] WHERE [isIdentity] = 1;

END
GO

/****** Object:  StoredProcedure [dbo].[GetRoleClaimType] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[GetRoleClaimType]
AS
BEGIN
	SET NOCOUNT ON;

	SELECT TOP 1 [ClaimType] FROM [ClaimTypeMapping] WHERE [isRole] = 1;

END

GO
/****** Object:  StoredProcedure [dbo].[GetUser] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[GetUser]
	@Identity nvarchar(255),
	@isLogin bit,
	@createUser bit
AS
BEGIN
	SET NOCOUNT ON;

	DECLARE @UserID INT

	SELECT @UserID = [ID] FROM [Users] WHERE [Users].[Identity] = RTRIM(LTRIM(LOWER(@Identity)));

	IF @createUser = 1 AND @UserID IS NULL
		BEGIN
			INSERT INTO [Users] ([Identity], [isApproved], [isSecurityApproved], [isTOUAccepted], [CreateDate], [LastModifiedDate], [LoginCount]) VALUES (RTRIM(LTRIM(LOWER(@Identity))), 0, 0, 0, GETDATE(), GETDATE(), 0);
			SELECT @UserID = @@IDENTITY;
		END

	IF(@isLogin) = 1
		BEGIN
			UPDATE [Users] SET [LastLoginDate] = GETDATE(), LoginCount = LoginCount + 1 WHERE ID = @UserID;
		END
	 
SELECT * FROM [Users] WHERE [ID] = @UserID;
		
END
GO
/****** Object:  StoredProcedure [dbo].[GetUserProfileProperties] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[GetUserProfileProperties]
	@UserID INT
AS
BEGIN
	SET NOCOUNT ON;
	 
SELECT [PropertyName], [PropertyValue] FROM [UserProperties] WHERE [UserID] = @UserID;
	
END
GO
/****** Object:  StoredProcedure [dbo].[GetUserRoles] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO


CREATE PROCEDURE [dbo].[GetUserRoles]
	@UserID INT
AS
BEGIN
	SET NOCOUNT ON;

	SELECT UR.[ID], CTP.[ClaimType], UR.[RoleName], UR.[CreateDate], UR.[LastModifiedDate]
	FROM [dbo].[UserRoles] UR
	INNER JOIN [dbo].[ClaimTypeMapping] CTP ON CTP.ID = UR.ClaimTypeMappingID
	WHERE UR.[UserID] = @UserID AND UR.[Active] = 1;
	
END
GO
/****** Object:  StoredProcedure [dbo].[LogClaim] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[LogClaim]
	@Identity nvarchar(255),
	@ClaimType nvarchar(255),
	@ClaimValue nvarchar(255)
AS
BEGIN
	SET NOCOUNT ON;

DECLARE @RoleClaim nvarchar(255)
DECLARE @UserID INT

SELECT @RoleClaim = [ClaimType] FROM [ClaimTypeMapping] WHERE [ClaimTypeMapping].[isRole] = 1
SELECT @UserID = [ID] FROM [Users] WHERE [Users].[Identity] = RTRIM(LTRIM(LOWER(@Identity)));

IF @UserID IS NOT NULL
BEGIN
	MERGE [dbo].[Claims] WITH(HOLDLOCK) as C
	USING (SELECT @ClaimType, @ClaimValue) AS [Source] ([ClaimType], [ClaimValue])
	ON C.ClaimType = [Source].[ClaimType] AND [Source].[ClaimType] <> @RoleClaim AND C.UserID = @UserID
	WHEN MATCHED THEN
		UPDATE SET C.ClaimValue = [Source].[ClaimValue], C.DateTime = GETDATE()
	WHEN NOT MATCHED BY TARGET AND @ClaimType <> @RoleClaim THEN
		INSERT ([UserID], [ClaimType], [ClaimValue], [DateTime])
		VALUES (@UserID, [Source].[ClaimType], [Source].[ClaimValue], GETDATE());

	MERGE [dbo].[Claims] WITH(HOLDLOCK) as C
	USING (SELECT @ClaimType, @ClaimValue) AS [Source] ([ClaimType], [ClaimValue])
	ON C.ClaimType = [Source].[ClaimType] AND C.ClaimValue = [Source].[ClaimValue]
	AND [Source].[ClaimType] = @RoleClaim AND C.UserID = @UserID
	WHEN MATCHED THEN
		UPDATE SET C.DateTime = GETDATE()
	WHEN NOT MATCHED BY TARGET AND @ClaimType = @RoleClaim THEN
		INSERT ([UserID], [ClaimType], [ClaimValue], [DateTime])
		VALUES (@UserID, [Source].[ClaimType], [Source].[ClaimValue], GETDATE());

IF EXISTS (SELECT [ClaimTypeMapping].[UserPropertyName] FROM [ClaimTypeMapping] WHERE [ClaimTypeMapping].[ClaimType] = @ClaimType)
BEGIN
	DECLARE @UserPropertyName nvarchar(255)
	DECLARE @ClaimTypeMappingID int
	DECLARE @isIdentity bit
	DECLARE @isRole bit
	DECLARE @isDisplayName bit
	DECLARE @isEmail bit

	SELECT
		@UserPropertyName = [ClaimTypeMapping].[UserPropertyName],
		@ClaimTypeMappingID = [ClaimTypeMapping].[ID],
		@isIdentity = [ClaimTypeMapping].[isIdentity],
		@isRole = [ClaimTypeMapping].[isRole],
		@isDisplayName = [ClaimTypeMapping].[isDisplayName],
		@isEmail = [ClaimTypeMapping].[isEmail]
	FROM [ClaimTypeMapping]
	WHERE [ClaimTypeMapping].[ClaimType] = @ClaimType

	MERGE [dbo].[UserProperties] WITH(HOLDLOCK) as UP
	USING (SELECT @UserPropertyName, @ClaimTypeMappingID, @ClaimValue) AS [Source] ([UserPropertyName], [ClaimTypeMappingID], [ClaimValue])
	ON UP.ClaimTypeMappingID = [Source].[ClaimTypeMappingID] AND UP.Userid = @UserID
	WHEN MATCHED AND @isRole = 0 THEN
		UPDATE SET UP.PropertyValue = [Source].[ClaimValue]
	WHEN NOT MATCHED BY TARGET AND @isRole = 0 THEN
		INSERT ([UserID], [ClaimTypeMappingID], [PropertyName], [PropertyValue])
		VALUES (@UserID, [Source].[ClaimTypeMappingID], [Source].[UserPropertyName], [Source].[ClaimValue]);
	
	IF (@isRole = 1)
	BEGIN
		MERGE [dbo].[UserRoles] WITH(HOLDLOCK) as UR
		USING (SELECT @ClaimTypeMappingID, @ClaimValue) AS [Source] ([ClaimTypeMappingID], [ClaimValue])
		ON UR.RoleName = [Source].[ClaimValue] AND UR.UserID = @UserID
		WHEN MATCHED THEN
			UPDATE SET UR.LastModifiedDate = GETDATE(), UR.Active = 1
		WHEN NOT MATCHED BY TARGET THEN
			INSERT ([UserID], [ClaimTypeMappingID], [RoleName], [CreateDate], [LastModifiedDate], [Active])
			VALUES (@UserID, [Source].[ClaimTypeMappingID], [Source].[ClaimValue], GETDATE(), GETDATE(), 1);
	END

	IF (@isDisplayName = 1)
	BEGIN
		UPDATE [Users] SET [DisplayName] = @ClaimValue WHERE [ID] = @UserID;
	END

	IF (@isEmail = 1)
	BEGIN
		UPDATE [Users] SET [EmailAddress] = @ClaimValue WHERE [ID] = @UserID;
	END

END

END

END
GO
/****** Object:  StoredProcedure [dbo].[LogMessage] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[LogMessage]
	@Message text = NULL,
	@Severity varchar(50) = NULL,
	@Server varchar(50) = NULL,
	@EventID int = 0,
	@StackTrace text = NULL,
	@ExceptionMessage text = NULL,
	@InnerExceptionStackTrace text = NULL

AS
BEGIN
	SET NOCOUNT ON;
	DECLARE @session_usr nchar(30);
	SET @session_usr = SESSION_USER;

INSERT INTO [dbo].[Messages]
           ([Created],[Message],[Severity],[Server],[StackTrace],[ExceptionMessage],[InnerExceptionStackTrace],[SessionUser],[EventID])
     VALUES
           (GETDATE(), @Message, @Severity, @Server, @StackTrace, @ExceptionMessage, @InnerExceptionStackTrace, @session_usr, @EventID)
END
GO
/****** Object:  StoredProcedure [dbo].[LookupUsers] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[LookupUsers]
	@Query nvarchar(255),
	@QueryType INT
	
AS
BEGIN
	SET NOCOUNT ON;

	IF @QueryType = 1
		BEGIN
			SELECT * FROM [dbo].[Users] WHERE (RTRIM(LTRIM(LOWER([IDENTITY]))) LIKE '%' + @Query + '%' OR RTRIM(LTRIM(LOWER([EmailAddress]))) LIKE '%' + @Query + '%' OR RTRIM(LTRIM(LOWER([DisplayName]))) LIKE '%' + @Query + '%');
		END

	IF @QueryType = 2
		BEGIN
			SELECT U.* FROM [dbo].[Users] U
				 INNER JOIN [dbo].ClaimTypeMapping CTP on CTP.isDisplayName = 1
				 INNER JOIN [dbo].[UserProperties] UP on UP.ClaimTypeMappingID = CTP.ID AND UP.UserID = U.ID
				WHERE CTP.isDisplayName = 1 AND UP.PropertyValue like '%' + @Query + '%';
		END

	IF @QueryType = 3
		BEGIN
			SELECT DISTINCT U.* FROM [dbo].[Users] U
				 INNER JOIN [dbo].[UserProperties] UP ON UP.UserID = U.ID
				WHERE  UP.PropertyValue like '%' + @Query + '%';
		END

	IF @QueryType = 4
		BEGIN
			SELECT * FROM [dbo].[Users] WHERE RTRIM(LTRIM(LOWER([IDENTITY]))) LIKE '%' + @Query + '%';
		END
END
GO
/****** Object:  StoredProcedure [dbo].[SaveUser] ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[SaveUser]
	@ID int,
	@Identity nvarchar(255),
	@isApproved bit,
	@isSecurityApproved bit,
	@isTOUAccepted bit
AS
BEGIN
	SET NOCOUNT ON;
	
MERGE [dbo].[Users] WITH(HOLDLOCK) as U
USING (SELECT @ID, @Identity, @isApproved, @isSecurityApproved, @isTOUAccepted) AS [Source] ([ID], [Identity], [isApproved], [isSecurityApproved], [isTOUAccepted])
ON  U.ID  = [Source].[ID]
WHEN MATCHED THEN
	UPDATE SET
	[U].[Identity] = [Source].[Identity],
	[U].[isApproved] = [Source].[isApproved],
	[U].[isSecurityApproved] = [Source].[isSecurityApproved],
	[U].[isTOUAccepted] = [Source].[isTOUAccepted],
	[U].[LastModifiedDate] = GETDATE()
WHEN NOT MATCHED BY TARGET THEN
	INSERT ([Identity], [isApproved], [isSecurityApproved], [isTOUAccepted], [CreateDate], [LastModifiedDate])
	VALUES ([Source].[Identity], [Source].[isApproved], [Source].[isSecurityApproved], [Source].[isTOUAccepted], GETDATE(), GETDATE());

END
GO
/****** Object:  StoredProcedure [dbo].[SetRolesInactive] ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[SetRolesInactive]
	@UserID INT
AS
BEGIN
	SET NOCOUNT ON;

	IF @UserID IS NOT NULL
		BEGIN
			UPDATE [UserRoles] SET [Active] = 0 WHERE [UserID] = @UserID;
		END

END
GO

INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name','DisplayName',0,0,1,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress','EmailAddress',1,0,0,1);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname','FirstName',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname','LastName',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier','PersonGUID',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress','StreetAddress',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality','City',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince','State',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode','ZipCode',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country','Country',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn','UPN',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/otherphone','WorkPhone',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone','HomePhone',0,0,0,0);
INSERT INTO [dbo].[ClaimTypeMapping]
([ClaimType],[UserPropertyName],[isIdentity],[isRole],[isDisplayName],[isEmail])
VALUES ('http://schemas.microsoft.com/ws/2008/06/identity/claims/role','Role',0,1,0,0);
GO
