import React, { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus, Trash2, RefreshCw, Copy, Activity, User, Settings } from 'lucide-react';
import { request as invoke } from '../utils/request';
import { showToast } from '../components/common/ToastContainer';

interface UserToken {
    id: string;
    token: string;
    username: string;
    description?: string;
    enabled: boolean;
    expires_type: string;
    expires_at?: number;
    max_ips: number;
    curfew_start?: string;
    curfew_end?: string;
    created_at: number;
    updated_at: number;
    last_used_at?: number;
    total_requests: number;
    total_tokens_used: number;
}

interface UserTokenStats {
    total_tokens: number;
    active_tokens: number;
    total_users: number;
    today_requests: number;
}

// interface CreateTokenRequest omitted as it's not explicitly used for typing variables

const UserToken: React.FC = () => {
    const { t } = useTranslation();
    const [tokens, setTokens] = useState<UserToken[]>([]);
    const [stats, setStats] = useState<UserTokenStats | null>(null);
    const [loading, setLoading] = useState(false);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [creating, setCreating] = useState(false);

    // Edit State
    const [showEditModal, setShowEditModal] = useState(false);
    const [editingToken, setEditingToken] = useState<UserToken | null>(null);
    const [editUsername, setEditUsername] = useState('');
    const [editDesc, setEditDesc] = useState('');
    const [editMaxIps, setEditMaxIps] = useState(0);
    const [editCurfewStart, setEditCurfewStart] = useState('');
    const [editCurfewEnd, setEditCurfewEnd] = useState('');
    const [updating, setUpdating] = useState(false);

    // Create Form State
    const [newUsername, setNewUsername] = useState('');
    const [newDesc, setNewDesc] = useState('');
    const [newExpiresType, setNewExpiresType] = useState('month'); // day, week, month, never
    const [newMaxIps, setNewMaxIps] = useState(0);
    const [newCurfewStart, setNewCurfewStart] = useState('');
    const [newCurfewEnd, setNewCurfewEnd] = useState('');

    const loadData = async () => {
        setLoading(true);
        try {
            const [tokensData, statsData] = await Promise.all([
                invoke<UserToken[]>('list_user_tokens'),
                invoke<UserTokenStats>('get_user_token_summary')
            ]);
            setTokens(tokensData);
            setStats(statsData);
        } catch (e) {
            console.error('Failed to load user tokens', e);
            showToast(t('common.load_failed') || 'Failed to load data', 'error');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadData();
    }, []);

    const handleCreate = async () => {
        if (!newUsername) {
            showToast(t('user_token.username_required') || 'Username is required', 'error');
            return;
        }

        setCreating(true);
        try {
            await invoke('create_user_token', {
                request: {
                    username: newUsername,
                    expires_type: newExpiresType,
                    description: newDesc || undefined,
                    max_ips: newMaxIps,
                    curfew_start: newCurfewStart || undefined,
                    curfew_end: newCurfewEnd || undefined
                }
            });
            showToast(t('common.create_success') || 'Created successfully', 'success');
            setShowCreateModal(false);
            setNewUsername('');
            setNewDesc('');
            setNewExpiresType('month');
            setNewMaxIps(0);
            setNewCurfewStart('');
            setNewCurfewEnd('');
            loadData();
        } catch (e) {
            console.error('Failed to create token', e);
            showToast(String(e), 'error');
        } finally {
            setCreating(false);
        }
    };

    const handleDelete = async (id: string) => {
        try {
            await invoke('delete_user_token', { id });
            showToast(t('common.delete_success') || 'Deleted successfully', 'success');
            loadData();
        } catch (e) {
            showToast(String(e), 'error');
        }
    };

    const handleEdit = (token: UserToken) => {
        setEditingToken(token);
        setEditUsername(token.username);
        setEditDesc(token.description || '');
        setEditMaxIps(token.max_ips);
        setEditCurfewStart(token.curfew_start || '');
        setEditCurfewEnd(token.curfew_end || '');
        setShowEditModal(true);
    };

    const handleUpdate = async () => {
        if (!editingToken) return;
        if (!editUsername) {
            showToast(t('user_token.username_required') || 'Username is required', 'error');
            return;
        }

        setUpdating(true);
        try {
            await invoke('update_user_token', {
                id: editingToken.id,
                request: {
                    username: editUsername,
                    description: editDesc || undefined,
                    max_ips: editMaxIps,
                    curfew_start: editCurfewStart || null,
                    curfew_end: editCurfewEnd || null
                }
            });
            showToast(t('common.update_success') || 'Updated successfully', 'success');
            setShowEditModal(false);
            setEditingToken(null);
            loadData();
        } catch (e) {
            console.error('Failed to update token', e);
            showToast(String(e), 'error');
        } finally {
            setUpdating(false);
        }
    };

    const handleRenew = async (id: string, type: string) => {
        try {
            await invoke('renew_user_token', { id, expiresType: type });
            showToast(t('user_token.renew_success') || 'Renewed successfully', 'success');
            loadData();
        } catch (e) {
            showToast(String(e), 'error');
        }
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        showToast(t('common.copied') || 'Copied to clipboard', 'success');
    };

    const formatTime = (ts?: number) => {
        if (!ts) return '-';
        return new Date(ts * 1000).toLocaleString();
    };

    const getExpiresLabel = (type: string) => {
        switch (type) {
            case 'day': return t('user_token.expires_day', { defaultValue: '1 Day' });
            case 'week': return t('user_token.expires_week', { defaultValue: '1 Week' });
            case 'month': return t('user_token.expires_month', { defaultValue: '1 Month' });
            case 'never': return t('user_token.expires_never', { defaultValue: 'Never' });
            default: return type;
        }
    };

    // Calculate expiration status style
    const getExpiresStatus = (expiresAt?: number) => {
        if (!expiresAt) return 'text-green-500';
        const now = Date.now() / 1000;
        if (expiresAt < now) return 'text-red-500 font-bold';
        if (expiresAt - now < 86400 * 3) return 'text-orange-500'; // Less than 3 days
        return 'text-green-500';
    };

    return (
        <div className="h-full flex flex-col p-5 gap-4 max-w-7xl mx-auto w-full">
            {/* Header */}
            <div className="flex items-center">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                    <User className="text-purple-500" />
                    {t('user_token.title', { defaultValue: 'User Tokens' })}
                </h1>
            </div>

            {/* Stats Cards Row with Action Buttons */}
            <div className="flex items-center gap-4">
                {/* Stats Cards */}
                <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="stats shadow bg-white dark:bg-base-100 border border-gray-100 dark:border-base-200">
                        <div className="stat">
                            <div className="stat-figure text-primary">
                                <User size={24} />
                            </div>
                            <div className="stat-title">{t('user_token.total_users', { defaultValue: 'Total Users' })}</div>
                            <div className="stat-value text-primary">{stats?.total_users || 0}</div>
                        </div>
                    </div>
                    <div className="stats shadow bg-white dark:bg-base-100 border border-gray-100 dark:border-base-200">
                        <div className="stat">
                            <div className="stat-figure text-secondary">
                                <Activity size={24} />
                            </div>
                            <div className="stat-title">{t('user_token.active_tokens', { defaultValue: 'Active Tokens' })}</div>
                            <div className="stat-value text-secondary">{stats?.active_tokens || 0}</div>
                            <div className="stat-desc">{t('user_token.total_created', { defaultValue: 'Total' })}: {stats?.total_tokens || 0}</div>
                        </div>
                    </div>
                    {/* You can add more stats cards here */}
                </div>

                {/* Action Buttons - 与卡片对齐 */}
                <div className="flex items-center gap-2 self-stretch">
                    <button
                        onClick={() => loadData()}
                        className="btn btn-ghost btn-sm btn-square"
                        title={t('common.refresh') || 'Refresh'}
                    >
                        <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
                    </button>
                    <button
                        onClick={() => setShowCreateModal(true)}
                        className="btn btn-sm btn-primary gap-2 px-4"
                    >
                        <Plus size={16} />
                        <span>{t('user_token.create', { defaultValue: 'Create Token' })}</span>
                    </button>
                </div>
            </div>

            {/* Token List */}
            <div className="flex-1 overflow-auto bg-white dark:bg-base-100 rounded-xl shadow-sm border border-gray-100 dark:border-base-200">
                <table className="table table-pin-rows">
                    <thead>
                        <tr>
                            <th>{t('user_token.username', { defaultValue: 'Username' })}</th>
                            <th>{t('user_token.token', { defaultValue: 'Token' })}</th>
                            <th>{t('user_token.expires', { defaultValue: 'Expires' })}</th>
                            <th>{t('user_token.usage', { defaultValue: 'Usage' })}</th>
                            <th>{t('user_token.ip_limit', { defaultValue: 'IP Limit' })}</th>
                            <th>{t('user_token.created', { defaultValue: 'Created' })}</th>
                            <th className="text-right">{t('common.actions', { defaultValue: 'Actions' })}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tokens.map(token => (
                            <tr key={token.id} className="hover">
                                <td>
                                    <div className="font-bold">{token.username}</div>
                                    <div className="text-xs text-gray-500">{token.description}</div>
                                </td>
                                <td>
                                    <div className="flex items-center gap-2 group">
                                        <code className="bg-gray-100 dark:bg-base-200 px-1 py-0.5 rounded text-xs truncate max-w-[100px] block">
                                            {token.token.substring(0, 12)}...
                                        </code>
                                        <button
                                            onClick={() => copyToClipboard(token.token)}
                                            className="opacity-0 group-hover:opacity-100 btn btn-ghost btn-xs btn-square"
                                        >
                                            <Copy size={12} />
                                        </button>
                                    </div>
                                </td>
                                <td>
                                    <div className={`text-sm ${getExpiresStatus(token.expires_at)}`}>
                                        {token.expires_at ? formatTime(token.expires_at) : t('user_token.never', { defaultValue: 'Never' })}
                                    </div>
                                    <div className="text-xs text-gray-500">
                                        {getExpiresLabel(token.expires_type)}
                                        {token.expires_at && token.expires_at < Date.now() / 1000 && (
                                            <button
                                                onClick={() => handleRenew(token.id, token.expires_type)}
                                                className="ml-2 text-blue-500 hover:underline"
                                            >
                                                {t('user_token.renew_button', { defaultValue: 'Renew' })}
                                            </button>
                                        )}
                                    </div>
                                </td>
                                <td>
                                    <div className="text-sm">{token.total_requests} reqs</div>
                                    <div className="text-xs text-gray-500">
                                        {(token.total_tokens_used / 1000).toFixed(1)}k tokens
                                    </div>
                                </td>
                                <td>
                                    {token.max_ips === 0
                                        ? <span className="badge badge-ghost badge-sm">{t('user_token.unlimited', { defaultValue: 'Unlimited' })}</span>
                                        : <span className="badge badge-outline badge-sm">{token.max_ips} IPs</span>
                                    }
                                    {token.curfew_start && token.curfew_end && (
                                        <div className="text-[10px] text-orange-500 mt-1 flex items-center gap-1">
                                            <span title="Curfew Active">🚫</span>
                                            {token.curfew_start} - {token.curfew_end}
                                        </div>
                                    )}
                                </td>
                                <td className="text-xs text-gray-500">
                                    {formatTime(token.created_at)}
                                </td>
                                <td className="text-right">
                                    <div className="flex justify-end gap-1">
                                        <button
                                            onClick={() => handleEdit(token)}
                                            className="btn btn-ghost btn-xs"
                                            title={t('common.edit', { defaultValue: 'Edit' })}
                                        >
                                            <Settings size={14} />
                                        </button>
                                        <div className="dropdown dropdown-end">
                                            <label tabIndex={0} className="btn btn-ghost btn-xs">
                                                {t('user_token.renew', { defaultValue: 'Renew' })}
                                            </label>
                                            <ul tabIndex={0} className="dropdown-content z-[1] menu p-2 shadow bg-base-100 rounded-box w-32 border border-base-200">
                                                <li><a onClick={() => handleRenew(token.id, 'day')}>{t('user_token.expires_day', { defaultValue: '1 Day' })}</a></li>
                                                <li><a onClick={() => handleRenew(token.id, 'week')}>{t('user_token.expires_week', { defaultValue: '1 Week' })}</a></li>
                                                <li><a onClick={() => handleRenew(token.id, 'month')}>{t('user_token.expires_month', { defaultValue: '1 Month' })}</a></li>
                                            </ul>
                                        </div>
                                        <button
                                            onClick={() => handleDelete(token.id)}
                                            className="btn btn-ghost btn-xs text-error"
                                        >
                                            <Trash2 size={14} />
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        ))}
                        {tokens.length === 0 && !loading && (
                            <tr>
                                <td colSpan={7} className="text-center py-10 text-gray-400">
                                    {t('user_token.no_data', { defaultValue: 'No tokens found' })}
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Create Modal */}
            {showCreateModal && (
                <div className="modal modal-open">
                    <div className="modal-box">
                        <h3 className="font-bold text-lg mb-4">{t('user_token.create_title', { defaultValue: 'Create New Token' })}</h3>

                        <div className="form-control w-full mb-3">
                            <label className="label">
                                <span className="label-text">{t('user_token.username', { defaultValue: 'Username' })} *</span>
                            </label>
                            <input
                                type="text"
                                className="input input-bordered w-full"
                                value={newUsername}
                                onChange={e => setNewUsername(e.target.value)}
                                placeholder={t('user_token.placeholder_username', { defaultValue: 'e.g. user1' })}
                            />
                        </div>

                        <div className="form-control w-full mb-3">
                            <label className="label">
                                <span className="label-text">{t('user_token.description', { defaultValue: 'Description' })}</span>
                            </label>
                            <input
                                type="text"
                                className="input input-bordered w-full"
                                value={newDesc}
                                onChange={e => setNewDesc(e.target.value)}
                                placeholder={t('user_token.placeholder_desc', { defaultValue: 'Optional notes' })}
                            />
                        </div>

                        <div className="grid grid-cols-2 gap-4 mb-3">
                            <div className="form-control w-full">
                                <label className="label">
                                    <span className="label-text">{t('user_token.expires', { defaultValue: 'Expires In' })}</span>
                                </label>
                                <select
                                    className="select select-bordered w-full"
                                    value={newExpiresType}
                                    onChange={e => setNewExpiresType(e.target.value)}
                                >
                                    <option value="day">{t('user_token.expires_day', { defaultValue: '1 Day' })}</option>
                                    <option value="week">{t('user_token.expires_week', { defaultValue: '1 Week' })}</option>
                                    <option value="month">{t('user_token.expires_month', { defaultValue: '1 Month' })}</option>
                                    <option value="never">{t('user_token.expires_never', { defaultValue: 'Never' })}</option>
                                </select>
                            </div>

                            <div className="form-control w-full">
                                <label className="label">
                                    <span className="label-text">{t('user_token.ip_limit', { defaultValue: 'Max IPs' })}</span>
                                </label>
                                <input
                                    type="number"
                                    className="input input-bordered w-full"
                                    value={newMaxIps}
                                    onChange={e => setNewMaxIps(parseInt(e.target.value) || 0)}
                                    min="0"
                                    placeholder={t('user_token.placeholder_max_ips', { defaultValue: '0 = Unlimited' })}
                                />
                                <label className="label">
                                    <span className="label-text-alt text-gray-500">{t('user_token.hint_max_ips', { defaultValue: '0 = Unlimited' })}</span>
                                </label>
                            </div>
                        </div>

                        <div className="form-control w-full mb-3">
                            <label className="label">
                                <span className="label-text">{t('user_token.curfew', { defaultValue: 'Curfew (Service Unavailable Time)' })}</span>
                            </label>
                            <div className="flex gap-2 items-center">
                                <input
                                    type="time"
                                    className="input input-bordered w-full"
                                    value={newCurfewStart}
                                    onChange={e => setNewCurfewStart(e.target.value)}
                                />
                                <span className="text-gray-400">to</span>
                                <input
                                    type="time"
                                    className="input input-bordered w-full"
                                    value={newCurfewEnd}
                                    onChange={e => setNewCurfewEnd(e.target.value)}
                                />
                            </div>
                            <label className="label">
                                <span className="label-text-alt text-gray-500">{t('user_token.hint_curfew', { defaultValue: 'Leave empty to disable. Based on server time.' })}</span>
                            </label>
                        </div>

                        <div className="modal-action">
                            <button className="btn" onClick={() => setShowCreateModal(false)}>
                                {t('common.cancel', { defaultValue: 'Cancel' })}
                            </button>
                            <button
                                className={`btn btn-primary ${creating ? 'loading' : ''}`}
                                onClick={handleCreate}
                                disabled={creating}
                            >
                                {t('common.create', { defaultValue: 'Create' })}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Edit Modal */}
            {showEditModal && editingToken && (
                <div className="modal modal-open">
                    <div className="modal-box">
                        <h3 className="font-bold text-lg mb-4">{t('user_token.edit_title', { defaultValue: 'Edit Token' })}</h3>

                        <div className="form-control w-full mb-3">
                            <label className="label">
                                <span className="label-text">{t('user_token.username', { defaultValue: 'Username' })} *</span>
                            </label>
                            <input
                                type="text"
                                className="input input-bordered w-full"
                                value={editUsername}
                                onChange={e => setEditUsername(e.target.value)}
                                placeholder={t('user_token.placeholder_username', { defaultValue: 'e.g. user1' })}
                            />
                        </div>

                        <div className="form-control w-full mb-3">
                            <label className="label">
                                <span className="label-text">{t('user_token.description', { defaultValue: 'Description' })}</span>
                            </label>
                            <input
                                type="text"
                                className="input input-bordered w-full"
                                value={editDesc}
                                onChange={e => setEditDesc(e.target.value)}
                                placeholder={t('user_token.placeholder_desc', { defaultValue: 'Optional notes' })}
                            />
                        </div>

                        <div className="form-control w-full mb-3">
                            <label className="label">
                                <span className="label-text">{t('user_token.ip_limit', { defaultValue: 'Max IPs' })}</span>
                            </label>
                            <input
                                type="number"
                                className="input input-bordered w-full"
                                value={editMaxIps}
                                onChange={e => setEditMaxIps(parseInt(e.target.value) || 0)}
                                min="0"
                                placeholder={t('user_token.placeholder_max_ips', { defaultValue: '0 = Unlimited' })}
                            />
                            <label className="label">
                                <span className="label-text-alt text-gray-500">{t('user_token.hint_max_ips', { defaultValue: '0 = Unlimited' })}</span>
                            </label>
                        </div>

                        <div className="form-control w-full mb-3">
                            <label className="label">
                                <span className="label-text">{t('user_token.curfew', { defaultValue: 'Curfew (Service Unavailable Time)' })}</span>
                            </label>
                            <div className="flex gap-2 items-center">
                                <input
                                    type="time"
                                    className="input input-bordered w-full"
                                    value={editCurfewStart}
                                    onChange={e => setEditCurfewStart(e.target.value)}
                                />
                                <span className="text-gray-400">to</span>
                                <input
                                    type="time"
                                    className="input input-bordered w-full"
                                    value={editCurfewEnd}
                                    onChange={e => setEditCurfewEnd(e.target.value)}
                                />
                            </div>
                            <label className="label">
                                <span className="label-text-alt text-gray-500">{t('user_token.hint_curfew', { defaultValue: 'Leave empty to disable. Based on server time.' })}</span>
                            </label>
                        </div>

                        <div className="modal-action">
                            <button className="btn" onClick={() => setShowEditModal(false)}>
                                {t('common.cancel', { defaultValue: 'Cancel' })}
                            </button>
                            <button
                                className={`btn btn-primary ${updating ? 'loading' : ''}`}
                                onClick={handleUpdate}
                                disabled={updating}
                            >
                                {t('common.update', { defaultValue: 'Update' })}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};
export default UserToken;
