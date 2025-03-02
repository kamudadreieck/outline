// @flow
import { observer } from "mobx-react";
import { DocumentIcon } from "outline-icons";
import * as React from "react";
import { useTranslation } from "react-i18next";
import { MenuButton, useMenuState } from "reakit/Menu";
import styled from "styled-components";
import Document from "models/Document";
import Button from "components/Button";
import ContextMenu from "components/ContextMenu";
import MenuItem from "components/ContextMenu/MenuItem";
import Separator from "components/ContextMenu/Separator";
import useStores from "hooks/useStores";

type Props = {|
  document: Document,
|};

function TemplatesMenu({ document }: Props) {
  const menu = useMenuState({ modal: true });
  const { documents } = useStores();
  const { t } = useTranslation();
  const templates = documents.templates;

  if (!templates.length) {
    return null;
  }

  const templatesInCollection = templates.filter(
    (t) => t.collectionId === document.collectionId
  );
  const otherTemplates = templates.filter(
    (t) => t.collectionId !== document.collectionId
  );

  const renderTemplate = (template) => (
    <MenuItem
      key={template.id}
      onClick={() => document.updateFromTemplate(template)}
      icon={<DocumentIcon />}
      {...menu}
    >
      <TemplateItem>
        <strong>{template.titleWithDefault}</strong>
        <br />
        <Author>
          {t("By {{ author }}", { author: template.createdBy.name })}
        </Author>
      </TemplateItem>
    </MenuItem>
  );

  return (
    <>
      <MenuButton {...menu}>
        {(props) => (
          <Button {...props} disclosure neutral>
            {t("Templates")}
          </Button>
        )}
      </MenuButton>
      <ContextMenu {...menu} aria-label={t("Templates")}>
        {templatesInCollection.map(renderTemplate)}
        {otherTemplates.length && templatesInCollection.length ? (
          <Separator />
        ) : undefined}
        {otherTemplates.map(renderTemplate)}
      </ContextMenu>
    </>
  );
}

const TemplateItem = styled.div`
  text-align: left;
`;

const Author = styled.div`
  font-size: 13px;
`;

export default observer(TemplatesMenu);
