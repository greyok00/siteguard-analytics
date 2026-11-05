<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

/**
 * Capability model. Each privileged surface has its own capability so an
 * editor can be given analytics without also being able to block visitors or
 * read the audit log.
 */
final class Caps
{
    public const VIEW_ANALYTICS = 'sg_view_analytics';
    public const VIEW_SECURITY = 'sg_view_security';
    public const MANAGE_BLOCKS = 'sg_manage_blocks';
    public const MANAGE_RULES = 'sg_manage_rules';
    public const MANAGE_SETTINGS = 'sg_manage_settings';
    public const EXPORT_DATA = 'sg_export_data';
    public const VIEW_AUDIT = 'sg_view_audit';

    /** @return list<string> */
    public static function all(): array
    {
        return [
            self::VIEW_ANALYTICS,
            self::VIEW_SECURITY,
            self::MANAGE_BLOCKS,
            self::MANAGE_RULES,
            self::MANAGE_SETTINGS,
            self::EXPORT_DATA,
            self::VIEW_AUDIT,
        ];
    }

    /** Grants every capability to administrators; nothing to other roles. */
    public static function install(): void
    {
        $role = get_role('administrator');
        if (!$role) {
            return;
        }
        foreach (self::all() as $cap) {
            $role->add_cap($cap, true);
        }
    }

    public static function remove(): void
    {
        $role = get_role('administrator');
        if (!$role) {
            return;
        }
        foreach (self::all() as $cap) {
            $role->remove_cap($cap);
        }
    }

    public static function userCan(string $capability): bool
    {
        return is_user_logged_in()
            && current_user_can($capability)
            && current_user_can('read');
    }
}
