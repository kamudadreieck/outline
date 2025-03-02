// @flow
import { type Context } from "koa";
import { User } from "./models";

export type ContextWithState = {|
  ...$Exact<Context>,
  state: {
    user: User,
    token: string,
    authType: "app" | "api",
  },
|};

export type UserEvent =
  | {
  name: | "users.create" // eslint-disable-line
        | "users.signin"
        | "users.update"
        | "users.suspend"
        | "users.activate"
        | "users.delete",
      userId: string,
      teamId: string,
      actorId: string,
      ip: string,
    }
  | {
      name: "users.invite",
      teamId: string,
      actorId: string,
      data: {
        email: string,
        name: string,
      },
      ip: string,
    };

export type DocumentEvent =
  | {
  name: | "documents.create" // eslint-disable-line
        | "documents.publish"
        | "documents.delete"
        | "documents.permanent_delete"
        | "documents.pin"
        | "documents.unpin"
        | "documents.archive"
        | "documents.unarchive"
        | "documents.restore"
        | "documents.star"
        | "documents.unstar",
      documentId: string,
      collectionId: string,
      teamId: string,
      actorId: string,
      ip: string,
      data: {
        title: string,
        source?: "import",
      },
    }
  | {
      name: "documents.move",
      documentId: string,
      collectionId: string,
      teamId: string,
      actorId: string,
      data: {
        collectionIds: string[],
        documentIds: string[],
      },
      ip: string,
    }
  | {
      name: | "documents.update" // eslint-disable-line
        | "documents.update.delayed"
        | "documents.update.debounced",
      documentId: string,
      collectionId: string,
      createdAt: string,
      teamId: string,
      actorId: string,
      data: {
        title: string,
        autosave: boolean,
        done: boolean,
      },
      ip: string,
    }
  | {
      name: "documents.title_change",
      documentId: string,
      collectionId: string,
      createdAt: string,
      teamId: string,
      actorId: string,
      data: {
        title: string,
        previousTitle: string,
      },
      ip: string,
    };

export type RevisionEvent = {
  name: "revisions.create",
  documentId: string,
  collectionId: string,
  teamId: string,
};

export type CollectionImportEvent = {
  name: "collections.import",
  modelId: string,
  teamId: string,
  actorId: string,
  data: { type: "outline" },
  ip: string,
};

export type CollectionExportAll = {
  name: "collections.export_all",
  teamId: string,
  actorId: string,
  data: {
    exportId: string,
    collections: [{ name: string, id: string }],
  },
};

export type FileOperationEvent = {
  name: "fileOperations.update",
  teamId: string,
  actorId: string,
  data: {
    type: string,
    state: string,
    id: string,
    size: number,
    createdAt: string,
    collectionId: string,
  },
};

export type CollectionEvent =
  | {
  name: | "collections.create" // eslint-disable-line
        | "collections.update"
        | "collections.delete",
      collectionId: string,
      teamId: string,
      actorId: string,
      data: { name: string },
      ip: string,
    }
  | {
      name: "collections.add_user" | "collections.remove_user",
      userId: string,
      collectionId: string,
      teamId: string,
      actorId: string,
      ip: string,
    }
  | {
      name: "collections.add_group" | "collections.remove_group",
      collectionId: string,
      teamId: string,
      actorId: string,
      data: { name: string, groupId: string },
      ip: string,
    }
  | {
      name: "collections.move",
      collectionId: string,
      teamId: string,
      actorId: string,
      data: { index: string },
      ip: string,
    }
  | {
      name: "collections.permission_changed",
      collectionId: string,
      teamId: string,
      actorId: string,
      data: {
        privacyChanged: boolean,
        sharingChanged: boolean,
      },
      ip: string,
    };

export type GroupEvent =
  | {
      name: "groups.create" | "groups.delete" | "groups.update",
      actorId: string,
      modelId: string,
      teamId: string,
      data: { name: string },
      ip: string,
    }
  | {
      name: "groups.add_user" | "groups.remove_user",
      actorId: string,
      userId: string,
      modelId: string,
      teamId: string,
      data: { name: string },
      ip: string,
    };

export type IntegrationEvent = {
  name: "integrations.create" | "integrations.update",
  modelId: string,
  teamId: string,
  actorId: string,
  ip: string,
};

export type TeamEvent = {
  name: "teams.update",
  teamId: string,
  actorId: string,
  data: Object,
  ip: string,
};

export type Event =
  | UserEvent
  | DocumentEvent
  | CollectionEvent
  | CollectionImportEvent
  | CollectionExportAll
  | FileOperationEvent
  | IntegrationEvent
  | GroupEvent
  | RevisionEvent
  | TeamEvent;
